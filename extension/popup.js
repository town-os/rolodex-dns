// Rolodex DNS enrollment popup.
//
// Talks to the same trusted-network `/api/*` surface the built-in web portal
// uses. The portal base URL is stored in extension storage; host permission for
// that origin is requested on demand (MV3 optional_host_permissions).
//
// The "CA via DNS" section is portal-independent: it retrieves the CA chain
// from DNS itself over DoH (CERT records preferred, prefixed TXT chunks as
// fallback), so it works for any client that can resolve the zone.

import { fetchCaChain, verifyDaneTa } from "./ca_dns.js";

const $ = (id) => document.getElementById(id);
const setStatus = (msg) => { $("status").textContent = msg; };

async function getPortal() {
  const { portal } = await chrome.storage.local.get("portal");
  return portal || "";
}

async function savePortal(url) {
  await chrome.storage.local.set({ portal: url });
}

// Ensure we hold host permission for the portal origin before fetching.
async function ensurePermission(url) {
  const origin = new URL(url).origin + "/*";
  const has = await chrome.permissions.contains({ origins: [origin] });
  if (has) return true;
  return chrome.permissions.request({ origins: [origin] });
}

function base() {
  return $("portal").value.replace(/\/+$/, "");
}

async function api(path, opts) {
  const url = base() + path;
  if (!(await ensurePermission(url))) {
    throw new Error("permission to access the portal was denied");
  }
  return fetch(url, opts);
}

async function loadZones() {
  setStatus("Loading zones…");
  try {
    const r = await api("/api/zones");
    const d = await r.json();
    const sel = $("zone");
    sel.innerHTML = "";
    (d.zones || []).forEach((z) => {
      const o = document.createElement("option");
      o.value = z; o.textContent = z; sel.appendChild(o);
    });
    setStatus((d.zones || []).length ? "" : "No zones configured yet.");
  } catch (e) {
    setStatus("Error: " + e.message);
  }
}

$("load").onclick = async () => {
  await savePortal(base());
  await loadZones();
};

$("enroll").onclick = async () => {
  setStatus("Enrolling…");
  try {
    const r = await api("/api/account", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ zone: $("zone").value }),
    });
    if (!r.ok) throw new Error(await r.text());
    const d = await r.json();
    const text = [
      "ACME directory: " + d.directory_url,
      "EAB key id:     " + d.eab_kid,
      "EAB HMAC key:   " + d.eab_hmac_key,
      "",
      ...(d.snippets || []),
    ].join("\n");
    $("result").textContent = text;
    $("out").classList.remove("hidden");
    setStatus("Enrolled. Copy the config into your ACME client.");
  } catch (e) {
    setStatus("Error: " + e.message);
  }
};

$("ca").onclick = async () => {
  try {
    const url = base() + "/api/ca";
    if (!(await ensurePermission(url))) throw new Error("permission denied");
    // Open in a tab so the browser handles the download/trust prompt.
    chrome.tabs.create({ url });
  } catch (e) {
    setStatus("Error: " + e.message);
  }
};

// --- CA via DNS (DoH) -------------------------------------------------------

async function getDoh() {
  const { doh } = await chrome.storage.local.get("doh");
  return doh || "";
}

function downloadPem(filename, pem) {
  const url = URL.createObjectURL(new Blob([pem], { type: "application/x-pem-file" }));
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

$("fetch-ca").onclick = async () => {
  const dohUrl = $("doh").value.trim();
  const zone = ($("dns-zone").value.trim() || $("zone").value || "").replace(/\.+$/, "");
  if (!dohUrl || !zone) {
    setStatus("DoH URL and zone are required.");
    return;
  }
  setStatus("Querying DNS for the CA chain…");
  try {
    await chrome.storage.local.set({ doh: dohUrl });
    if (!(await ensurePermission(dohUrl))) throw new Error("permission denied");

    const chain = await fetchCaChain(dohUrl, zone);
    const lines = [
      `Retrieved via ${chain.source === "cert" ? "CERT records (RFC 4398)" : "TXT fallback"}`,
      `root:         ${chain.root.der.length} bytes (self-signed)`,
      `intermediate: ${chain.intermediate.der.length} bytes`,
    ];

    const daneName = $("dane-name").value.trim();
    if (daneName) {
      const { records, verified } = await verifyDaneTa(dohUrl, daneName, chain.intermediate.der);
      if (verified === null) {
        lines.push(`DANE: no TLSA records published for ${daneName}`);
      } else if (verified) {
        lines.push(`DANE: ✓ intermediate matches TLSA at _443._tcp.${daneName}`);
      } else {
        lines.push(`DANE: ✗ intermediate does NOT match TLSA (${records.length} records)`);
      }
    }

    $("dns-result").textContent = lines.join("\n");
    $("dns-out").classList.remove("hidden");
    setStatus("CA chain retrieved from DNS.");

    const zoneSlug = zone.replace(/\./g, "-");
    $("dl-root").onclick = () => downloadPem("rolodex-root-ca.pem", chain.root.pem);
    $("dl-int").onclick = () =>
      downloadPem(`rolodex-${zoneSlug}-intermediate.pem`, chain.intermediate.pem);
    $("dl-chain").onclick = () =>
      downloadPem(
        `rolodex-${zoneSlug}-chain.pem`,
        chain.intermediate.pem + chain.root.pem,
      );
  } catch (e) {
    setStatus("Error: " + e.message);
  }
};

// Restore the saved portal and DoH URLs on open.
getPortal().then((p) => { if (p) { $("portal").value = p; loadZones(); } });
getDoh().then((d) => { if (d) $("doh").value = d; });
