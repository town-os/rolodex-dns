// CA retrieval over DNS for the Rolodex DNS extension.
//
// Rolodex publishes its CA chain into DNS so any client that can resolve the
// zone can obtain the root and per-zone intermediate certificates:
//
// - CERT records (RFC 4398) at `_ca.<zone>.` — preferred.
// - TXT records at `_rolodex-ca.<zone>.`, base64 DER chunked and framed as
//   `rolodex-ca:v1:<root|intermediate>:<i>/<n>:<chunk>` — fallback for
//   resolvers that cannot serve CERT.
//
// Browsers cannot speak raw DNS, so queries go over DoH (RFC 8484, POST
// `application/dns-message`) to the Rolodex DoH listener. This module is a
// browser-compatible ES module (Uint8Array/DataView/WebCrypto, no Node
// builtins) and is also imported by the Node test suite.

export const TXT_TYPE = 16;
export const CERT_TYPE = 37;
export const TLSA_TYPE = 52;

const CLASS_IN = 1;
const MAX_POINTER_JUMPS = 32;

/** Unique prefix framing Rolodex CA TXT chunks. */
export const CA_TXT_PREFIX = "rolodex-ca:v1";

/** Owner name carrying CA CERT records for a zone. */
export function caCertName(zone) {
  return `_ca.${String(zone).replace(/\.+$/, "")}.`;
}

/** Owner name carrying CA TXT chunk records for a zone. */
export function caTxtName(zone) {
  return `_rolodex-ca.${String(zone).replace(/\.+$/, "")}.`;
}

/** TLSA owner name: `_<port>._<protocol>.<domain>.` */
export function tlsaName(domain, port = 443, protocol = "tcp") {
  return `_${port}._${protocol}.${String(domain).replace(/\.+$/, "")}.`;
}

// --- DNS wire codec ---------------------------------------------------------

/** Encodes a domain name into DNS wire format. */
export function encodeName(name) {
  const labels = String(name)
    .replace(/\.+$/, "")
    .split(".")
    .filter((l) => l.length > 0);
  const out = [];
  const enc = new TextEncoder();
  for (const label of labels) {
    const bytes = enc.encode(label);
    if (bytes.length > 63) {
      throw new Error(`label too long: ${label}`);
    }
    out.push(bytes.length, ...bytes);
  }
  out.push(0);
  return new Uint8Array(out);
}

/** Encodes a DNS query for `name`/`type` with message id `id`. */
export function encodeQuery(name, type, id) {
  const qname = encodeName(name);
  const msg = new Uint8Array(12 + qname.length + 4);
  const view = new DataView(msg.buffer);
  view.setUint16(0, id);
  view.setUint16(2, 0x0100); // RD
  view.setUint16(4, 1); // QDCOUNT
  msg.set(qname, 12);
  view.setUint16(12 + qname.length, type);
  view.setUint16(12 + qname.length + 2, CLASS_IN);
  return msg;
}

/** Decodes a (possibly compressed) name at `offset`; returns {name, next}. */
export function decodeName(bytes, offset) {
  const labels = [];
  const dec = new TextDecoder();
  let pos = offset;
  let next = null;
  let jumps = 0;

  for (;;) {
    if (pos >= bytes.length) throw new Error("truncated name");
    const len = bytes[pos];
    if ((len & 0xc0) === 0xc0) {
      if (pos + 1 >= bytes.length) throw new Error("truncated pointer");
      if (next === null) next = pos + 2;
      pos = ((len & 0x3f) << 8) | bytes[pos + 1];
      if (++jumps > MAX_POINTER_JUMPS) throw new Error("pointer loop");
      continue;
    }
    if (len === 0) {
      if (next === null) next = pos + 1;
      break;
    }
    if (pos + 1 + len > bytes.length) throw new Error("truncated label");
    labels.push(dec.decode(bytes.subarray(pos + 1, pos + 1 + len)));
    pos += 1 + len;
  }
  return { name: labels.join(".") + ".", next };
}

/** Decodes a DNS message; answer rdata is returned as raw Uint8Array. */
export function decodeMessage(bytes) {
  if (bytes.length < 12) throw new Error("message too short");
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const id = view.getUint16(0);
  const flagsWord = view.getUint16(2);
  const flags = {
    qr: (flagsWord & 0x8000) !== 0,
    tc: (flagsWord & 0x0200) !== 0,
    rcode: flagsWord & 0x000f,
  };
  const qdcount = view.getUint16(4);
  const ancount = view.getUint16(6);

  let offset = 12;
  const questions = [];
  for (let i = 0; i < qdcount; i++) {
    const { name, next } = decodeName(bytes, offset);
    if (next + 4 > bytes.length) throw new Error("truncated question");
    questions.push({
      name,
      type: view.getUint16(next),
      class: view.getUint16(next + 2),
    });
    offset = next + 4;
  }

  const answers = [];
  for (let i = 0; i < ancount; i++) {
    const { name, next } = decodeName(bytes, offset);
    if (next + 10 > bytes.length) throw new Error("truncated answer");
    const type = view.getUint16(next);
    const klass = view.getUint16(next + 2);
    const ttl = view.getUint32(next + 4);
    const rdlength = view.getUint16(next + 8);
    const rdataStart = next + 10;
    if (rdataStart + rdlength > bytes.length) throw new Error("truncated rdata");
    answers.push({
      name,
      type,
      class: klass,
      ttl,
      rdata: bytes.subarray(rdataStart, rdataStart + rdlength),
    });
    offset = rdataStart + rdlength;
  }

  return { id, flags, questions, answers };
}

/** Parses CERT rdata (RFC 4398): type, key tag, algorithm, certificate DER. */
export function parseCertRdata(rdata) {
  if (rdata.length < 5) throw new Error("CERT rdata too short");
  const view = new DataView(rdata.buffer, rdata.byteOffset, rdata.byteLength);
  return {
    certType: view.getUint16(0),
    keyTag: view.getUint16(2),
    algorithm: rdata[4],
    certData: rdata.subarray(5),
  };
}

/** Parses TXT rdata into its character-strings. */
export function parseTxtRdata(rdata) {
  const dec = new TextDecoder();
  const strings = [];
  let pos = 0;
  while (pos < rdata.length) {
    const len = rdata[pos];
    if (pos + 1 + len > rdata.length) throw new Error("truncated TXT string");
    strings.push(dec.decode(rdata.subarray(pos + 1, pos + 1 + len)));
    pos += 1 + len;
  }
  return strings;
}

/** Parses TLSA rdata into {usage, selector, matchingType, data hex}. */
export function parseTlsaRdata(rdata) {
  if (rdata.length < 3) throw new Error("TLSA rdata too short");
  return {
    usage: rdata[0],
    selector: rdata[1],
    matchingType: rdata[2],
    data: bytesToHex(rdata.subarray(3)),
  };
}

// --- DoH transport ----------------------------------------------------------

/**
 * Sends one DNS query over DoH (RFC 8484 POST) and returns the decoded
 * message. `fetchFn` defaults to the global fetch and is injectable for
 * tests and environments needing custom TLS handling.
 */
export async function dohQuery(dohUrl, name, type, opts = {}) {
  const fetchFn = opts.fetchFn ?? fetch;
  const id = Math.floor(Math.random() * 0x10000);
  const query = encodeQuery(name, type, id);
  const res = await fetchFn(dohUrl, {
    method: "POST",
    headers: {
      "content-type": "application/dns-message",
      accept: "application/dns-message",
    },
    body: query,
  });
  if (!res.ok) {
    throw new Error(`DoH query failed: HTTP ${res.status}`);
  }
  const body = new Uint8Array(await res.arrayBuffer());
  const message = decodeMessage(body);
  if (message.id !== id) {
    throw new Error("DoH response id mismatch");
  }
  return message;
}

// --- base64 / hex / PEM -----------------------------------------------------

export function base64ToBytes(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function bytesToBase64(bytes) {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

export function bytesToHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

/** Wraps DER bytes as a CERTIFICATE PEM block. */
export function derToPem(der) {
  const b64 = bytesToBase64(der);
  const lines = b64.match(/.{1,64}/g) ?? [];
  return `-----BEGIN CERTIFICATE-----\n${lines.join("\n")}\n-----END CERTIFICATE-----\n`;
}

// --- minimal DER walking ----------------------------------------------------

/** Reads one DER TLV at `offset`; returns {tag, contentStart, contentEnd, end}. */
function derTlv(bytes, offset) {
  if (offset + 2 > bytes.length) throw new Error("truncated DER");
  const tag = bytes[offset];
  let len = bytes[offset + 1];
  let headerLen = 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 4 || offset + 2 + n > bytes.length) {
      throw new Error("unsupported DER length");
    }
    len = 0;
    for (let i = 0; i < n; i++) len = (len << 8) | bytes[offset + 2 + i];
    headerLen = 2 + n;
  }
  const contentStart = offset + headerLen;
  const contentEnd = contentStart + len;
  if (contentEnd > bytes.length) throw new Error("DER length out of range");
  return { tag, contentStart, contentEnd, end: contentEnd };
}

/** Lists the child TLVs of a constructed TLV. */
function derChildren(bytes, tlv) {
  const children = [];
  let pos = tlv.contentStart;
  while (pos < tlv.contentEnd) {
    const child = derTlv(bytes, pos);
    children.push({ ...child, start: pos });
    pos = child.end;
  }
  return children;
}

/**
 * Extracts the raw issuer, subject, and SubjectPublicKeyInfo TLVs from an
 * X.509 certificate DER (RFC 5280 TBSCertificate layout).
 */
export function parseCertificateFields(der) {
  const cert = derTlv(der, 0); // Certificate SEQUENCE
  const certParts = derChildren(der, cert);
  if (certParts.length < 1) throw new Error("malformed certificate");
  const tbsParts = derChildren(der, certParts[0]); // TBSCertificate SEQUENCE

  // version [0] is optional; when present it shifts the field positions.
  let idx = 0;
  if (tbsParts.length > 0 && tbsParts[0].tag === 0xa0) idx = 1;
  // serialNumber, signature, issuer, validity, subject, subjectPublicKeyInfo
  if (tbsParts.length < idx + 6) throw new Error("malformed TBSCertificate");
  const slice = (tlv) => der.subarray(tlv.start, tlv.end);
  return {
    issuer: slice(tbsParts[idx + 2]),
    subject: slice(tbsParts[idx + 4]),
    spki: slice(tbsParts[idx + 5]),
  };
}

function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

/** True when the certificate's issuer equals its subject (a root CA). */
export function isSelfSigned(der) {
  const { issuer, subject } = parseCertificateFields(der);
  return bytesEqual(issuer, subject);
}

/** SHA-256 of the certificate's SubjectPublicKeyInfo, lowercase hex. */
export async function spkiSha256Hex(der) {
  const { spki } = parseCertificateFields(der);
  const digest = await crypto.subtle.digest("SHA-256", spki);
  return bytesToHex(new Uint8Array(digest));
}

// --- CA retrieval -----------------------------------------------------------

/** Reassembles `rolodex-ca:v1:<kind>:<i>/<n>:<chunk>` TXT strings per kind. */
export function reassembleCaTxt(strings) {
  const byKind = new Map();
  for (const s of strings) {
    if (!s.startsWith(`${CA_TXT_PREFIX}:`)) continue;
    const parts = s.split(":");
    if (parts.length !== 5) continue;
    const [, , kind, seq, data] = parts;
    const [i, n] = seq.split("/").map(Number);
    if (!Number.isInteger(i) || !Number.isInteger(n) || i < 1 || i > n) continue;
    if (!byKind.has(kind)) byKind.set(kind, { total: n, chunks: new Map() });
    byKind.get(kind).chunks.set(i, data);
  }

  const out = {};
  for (const [kind, { total, chunks }] of byKind) {
    if (chunks.size !== total) {
      throw new Error(`incomplete ${kind} CA: ${chunks.size}/${total} chunks`);
    }
    let b64 = "";
    for (let i = 1; i <= total; i++) b64 += chunks.get(i);
    out[kind] = base64ToBytes(b64);
  }
  return out;
}

/**
 * Retrieves the CA chain for `zone` via DoH. Prefers CERT records (RFC 4398)
 * at `_ca.<zone>.`; falls back to prefixed TXT chunks at
 * `_rolodex-ca.<zone>.` when no usable CERT records are found.
 *
 * Returns `{ source, root, intermediate }` where root/intermediate are
 * `{ der, pem }` and `source` is `"cert"` or `"txt"`.
 */
export async function fetchCaChain(dohUrl, zone, opts = {}) {
  let ders = [];
  let source = "cert";

  try {
    const msg = await dohQuery(dohUrl, caCertName(zone), CERT_TYPE, opts);
    if (msg.flags.rcode === 0) {
      ders = msg.answers
        .filter((a) => a.type === CERT_TYPE)
        .map((a) => parseCertRdata(a.rdata))
        .filter((c) => c.certType === 1) // PKIX (X.509)
        .map((c) => c.certData);
    }
  } catch {
    // Fall through to the TXT fallback.
  }

  let root = null;
  let intermediate = null;

  if (ders.length > 0) {
    // CERT answers carry no kind labels and arrive in no guaranteed order;
    // the root is the self-signed certificate.
    for (const der of ders) {
      if (isSelfSigned(der)) root = der;
      else intermediate = der;
    }
  } else {
    source = "txt";
    const msg = await dohQuery(dohUrl, caTxtName(zone), TXT_TYPE, opts);
    if (msg.flags.rcode !== 0) {
      throw new Error(`CA TXT lookup failed with rcode ${msg.flags.rcode}`);
    }
    const strings = msg.answers
      .filter((a) => a.type === TXT_TYPE)
      .flatMap((a) => parseTxtRdata(a.rdata));
    const kinds = reassembleCaTxt(strings);
    root = kinds.root ?? null;
    intermediate = kinds.intermediate ?? null;
  }

  if (!root || !intermediate) {
    throw new Error(`no CA published in DNS for zone ${zone}`);
  }
  return {
    source,
    root: { der: root, pem: derToPem(root) },
    intermediate: { der: intermediate, pem: derToPem(intermediate) },
  };
}

/**
 * Verifies a certificate DER against the DANE-TA TLSA records published for
 * `domain` (Rolodex publishes `2 1 1` = SHA-256 of the intermediate's SPKI).
 * Returns `{ records, verified }`; `verified` is null when no records exist.
 */
export async function verifyDaneTa(dohUrl, domain, der, opts = {}) {
  const { port = 443, protocol = "tcp", ...dohOpts } = opts;
  const msg = await dohQuery(dohUrl, tlsaName(domain, port, protocol), TLSA_TYPE, dohOpts);
  if (msg.flags.rcode === 3) {
    return { records: [], verified: null };
  }
  if (msg.flags.rcode !== 0) {
    throw new Error(`TLSA lookup failed with rcode ${msg.flags.rcode}`);
  }
  const records = msg.answers
    .filter((a) => a.type === TLSA_TYPE)
    .map((a) => parseTlsaRdata(a.rdata));
  if (records.length === 0) {
    return { records, verified: null };
  }
  const spkiHash = await spkiSha256Hex(der);
  const verified = records.some(
    (r) => r.usage === 2 && r.selector === 1 && r.matchingType === 1 && r.data === spkiHash,
  );
  return { records, verified };
}
