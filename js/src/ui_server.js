// Local enrollment UI for the Rolodex ACME issuer.
//
// Serves a small web page (plain HTTP on a loopback/trusted bind) backed by
// two kinds of endpoints:
//
// - `/api/zones`, `/api/certs`, `/api/ca`, `/api/account` are proxied to the
//   enrollment portal over HTTPS. The proxy absorbs the portal's self-signed
//   certificate so the browser never has to trust it.
// - `/api/dane` performs a live TLSA lookup over the DNS wire protocol —
//   something a browser cannot do itself — and optionally verifies a pasted
//   PEM certificate (or chain) against the retrieved records.

import http from "node:http";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { PortalClient } from "./portal.js";
import { fetchTlsaRecords, matchDane, tlsaName, tlsaValue } from "./dane.js";

const UI_HTML = readFileSync(
  fileURLToPath(new URL("../ui/index.html", import.meta.url)),
  "utf8",
);

function readBody(req, limit = 1024 * 1024) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on("data", (c) => {
      size += c.length;
      if (size > limit) {
        reject(new Error("request body too large"));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

function sendJson(res, status, value) {
  const body = JSON.stringify(value);
  res.writeHead(status, {
    "content-type": "application/json",
    "content-length": Buffer.byteLength(body),
  });
  res.end(body);
}

/**
 * Creates the UI HTTP server.
 *
 * @param {object} opts
 * @param {string} opts.portalUrl Portal base URL (e.g. "https://127.0.0.1:8500").
 * @param {string|Buffer} [opts.ca] PEM CA to trust for the portal TLS cert.
 * @param {boolean} [opts.insecure] Skip portal TLS verification (self-signed).
 * @param {string} [opts.dnsServer] Default DNS server for DANE lookups.
 * @param {number} [opts.dnsPort] Default DNS port for DANE lookups (53).
 * @returns {http.Server}
 */
export function createUiServer(opts) {
  const portal = new PortalClient(opts.portalUrl, {
    ca: opts.ca,
    insecure: opts.insecure,
  });
  const defaultDnsServer = opts.dnsServer ?? "127.0.0.1";
  const defaultDnsPort = opts.dnsPort ?? 53;

  return http.createServer(async (req, res) => {
    const url = new URL(req.url, "http://localhost");
    try {
      if (req.method === "GET" && url.pathname === "/") {
        res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
        res.end(UI_HTML);
        return;
      }

      if (req.method === "GET" && url.pathname === "/api/zones") {
        sendJson(res, 200, { zones: await portal.listZones() });
        return;
      }

      if (req.method === "GET" && url.pathname === "/api/certs") {
        const zone = url.searchParams.get("zone");
        sendJson(res, 200, {
          certificates: await portal.listCertificates(zone),
        });
        return;
      }

      if (req.method === "GET" && url.pathname === "/api/ca") {
        const pem = await portal.getCaPem();
        res.writeHead(200, {
          "content-type": "application/x-pem-file",
          "content-disposition": 'attachment; filename="rolodex-root-ca.pem"',
        });
        res.end(pem);
        return;
      }

      if (req.method === "POST" && url.pathname === "/api/account") {
        const body = JSON.parse((await readBody(req)).toString("utf8"));
        if (!body.zone || typeof body.zone !== "string") {
          sendJson(res, 400, { error: "zone is required" });
          return;
        }
        sendJson(res, 200, await portal.createAccount(body.zone));
        return;
      }

      if (req.method === "POST" && url.pathname === "/api/dane") {
        const body = JSON.parse((await readBody(req)).toString("utf8"));
        if (!body.domain || typeof body.domain !== "string") {
          sendJson(res, 400, { error: "domain is required" });
          return;
        }
        const port = Number(body.port ?? 443);
        const protocol = body.protocol ?? "tcp";
        const fetched = await fetchTlsaRecords(body.domain, {
          port,
          protocol,
          dnsServer: body.dnsServer || defaultDnsServer,
          dnsPort: body.dnsPort ? Number(body.dnsPort) : defaultDnsPort,
          ...(body.transport ? { transport: body.transport } : {}),
        });
        const result = {
          name: tlsaName(body.domain, port, protocol),
          records: fetched.map((r) => ({ ...r, value: tlsaValue(r) })),
          verified: null,
          matchedIndex: null,
        };
        if (body.certPem) {
          const match = matchDane(fetched, body.certPem);
          result.verified = match !== null;
          result.matchedIndex = match ? fetched.indexOf(match.record) : null;
        }
        sendJson(res, 200, result);
        return;
      }

      sendJson(res, 404, { error: "not found" });
    } catch (err) {
      sendJson(res, 502, { error: String(err?.message ?? err) });
    }
  });
}
