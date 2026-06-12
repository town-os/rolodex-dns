// DANE/TLSA protocol retrieval and verification (RFC 6698).
//
// This module speaks the DNS wire protocol directly (UDP with automatic TCP
// fallback on truncation, or TCP on request) because Node's resolver API does
// not expose TLSA records. It also computes TLSA certificate association data
// from PEM certificates so retrieved records can be verified independently of
// the server that published them.
//
// Rolodex publishes DANE-TA records ("2 1 1 <sha256(intermediate SPKI)>") at
// `_<port>._<proto>.<name>.` on certificate issuance; `fetchTlsaRecords` plus
// `verifyCertAgainstTlsa` validate that contract end to end.

import dgram from "node:dgram";
import net from "node:net";
import crypto from "node:crypto";

/** DNS RR type code for TLSA (RFC 6698). */
export const TLSA_TYPE = 52;

/** DNS class IN. */
const CLASS_IN = 1;

/** Maximum compression-pointer jumps tolerated while decoding a name. */
const MAX_POINTER_JUMPS = 32;

/** Error raised for DNS protocol failures, carrying the response RCODE. */
export class DnsError extends Error {
  constructor(message, rcode = null) {
    super(message);
    this.name = "DnsError";
    this.rcode = rcode;
  }
}

/**
 * Constructs the TLSA owner name: `_<port>._<protocol>.<domain>.`
 * Mirrors `dane::tlsa_dns_name` on the Rust side.
 */
export function tlsaName(domain, port = 443, protocol = "tcp") {
  const trimmed = String(domain).replace(/\.+$/, "");
  return `_${port}._${protocol}.${trimmed}.`;
}

/** Encodes a domain name into DNS wire format (no compression). */
export function encodeName(name) {
  const labels = String(name)
    .replace(/\.+$/, "")
    .split(".")
    .filter((l) => l.length > 0);
  const parts = [];
  for (const label of labels) {
    const bytes = Buffer.from(label, "ascii");
    if (bytes.length > 63) {
      throw new DnsError(`label too long: ${label}`);
    }
    parts.push(Buffer.from([bytes.length]), bytes);
  }
  parts.push(Buffer.from([0]));
  return Buffer.concat(parts);
}

/**
 * Decodes a (possibly compressed) domain name at `offset`.
 * Returns `{ name, next }` where `next` is the offset just past the name in
 * the original (non-pointer) byte stream.
 */
export function decodeName(buf, offset) {
  const labels = [];
  let pos = offset;
  let next = null;
  let jumps = 0;

  for (;;) {
    if (pos >= buf.length) {
      throw new DnsError("truncated name");
    }
    const len = buf[pos];
    if ((len & 0xc0) === 0xc0) {
      if (pos + 1 >= buf.length) {
        throw new DnsError("truncated compression pointer");
      }
      if (next === null) {
        next = pos + 2;
      }
      pos = ((len & 0x3f) << 8) | buf[pos + 1];
      jumps += 1;
      if (jumps > MAX_POINTER_JUMPS) {
        throw new DnsError("compression pointer loop");
      }
      continue;
    }
    if (len === 0) {
      if (next === null) {
        next = pos + 1;
      }
      break;
    }
    if (pos + 1 + len > buf.length) {
      throw new DnsError("truncated label");
    }
    labels.push(buf.subarray(pos + 1, pos + 1 + len).toString("ascii"));
    pos += 1 + len;
  }

  return { name: labels.join(".") + ".", next };
}

/** Encodes a DNS query message for `name`/`type` with the given message id. */
export function encodeQuery(name, type, id) {
  const header = Buffer.alloc(12);
  header.writeUInt16BE(id, 0);
  header.writeUInt16BE(0x0100, 2); // RD set
  header.writeUInt16BE(1, 4); // QDCOUNT
  const question = Buffer.alloc(4);
  question.writeUInt16BE(type, 0);
  question.writeUInt16BE(CLASS_IN, 2);
  return Buffer.concat([header, encodeName(name), question]);
}

/**
 * Encodes a DNS response message. Used by tests and mock servers to exercise
 * the decoder against a symmetric implementation; answers carry raw rdata.
 *
 * `flags` is the 16-bit flags word (e.g. 0x8180 for a standard response).
 * Each answer is `{ name, type, ttl, rdata }`.
 */
export function encodeResponse({ id, flags = 0x8180, question = null, answers = [] }) {
  const header = Buffer.alloc(12);
  header.writeUInt16BE(id, 0);
  header.writeUInt16BE(flags, 2);
  header.writeUInt16BE(question ? 1 : 0, 4);
  header.writeUInt16BE(answers.length, 6);

  const parts = [header];
  if (question) {
    const q = Buffer.alloc(4);
    q.writeUInt16BE(question.type, 0);
    q.writeUInt16BE(CLASS_IN, 2);
    parts.push(encodeName(question.name), q);
  }
  for (const answer of answers) {
    const fixed = Buffer.alloc(10);
    fixed.writeUInt16BE(answer.type, 0);
    fixed.writeUInt16BE(CLASS_IN, 2);
    fixed.writeUInt32BE(answer.ttl ?? 0, 4);
    fixed.writeUInt16BE(answer.rdata.length, 8);
    parts.push(encodeName(answer.name), fixed, answer.rdata);
  }
  return Buffer.concat(parts);
}

/**
 * Decodes a DNS message into header flags, questions, and raw answers.
 * Answer rdata is returned as an uninterpreted Buffer.
 */
export function decodeMessage(buf) {
  if (buf.length < 12) {
    throw new DnsError("message too short");
  }
  const id = buf.readUInt16BE(0);
  const flagsWord = buf.readUInt16BE(2);
  const flags = {
    qr: (flagsWord & 0x8000) !== 0,
    tc: (flagsWord & 0x0200) !== 0,
    rcode: flagsWord & 0x000f,
  };
  const qdcount = buf.readUInt16BE(4);
  const ancount = buf.readUInt16BE(6);

  let offset = 12;
  const questions = [];
  for (let i = 0; i < qdcount; i++) {
    const { name, next } = decodeName(buf, offset);
    if (next + 4 > buf.length) {
      throw new DnsError("truncated question");
    }
    questions.push({
      name,
      type: buf.readUInt16BE(next),
      class: buf.readUInt16BE(next + 2),
    });
    offset = next + 4;
  }

  const answers = [];
  for (let i = 0; i < ancount; i++) {
    const { name, next } = decodeName(buf, offset);
    if (next + 10 > buf.length) {
      throw new DnsError("truncated answer");
    }
    const type = buf.readUInt16BE(next);
    const klass = buf.readUInt16BE(next + 2);
    const ttl = buf.readUInt32BE(next + 4);
    const rdlength = buf.readUInt16BE(next + 8);
    const rdataStart = next + 10;
    if (rdataStart + rdlength > buf.length) {
      throw new DnsError("truncated rdata");
    }
    answers.push({
      name,
      type,
      class: klass,
      ttl,
      rdata: buf.subarray(rdataStart, rdataStart + rdlength),
    });
    offset = rdataStart + rdlength;
  }

  return { id, flags, questions, answers };
}

/** Parses TLSA rdata into its RFC 6698 fields; `data` is lowercase hex. */
export function parseTlsaRdata(rdata) {
  if (rdata.length < 3) {
    throw new DnsError("TLSA rdata too short");
  }
  return {
    usage: rdata[0],
    selector: rdata[1],
    matchingType: rdata[2],
    data: rdata.subarray(3).toString("hex"),
  };
}

/** Encodes a TLSA record object back into rdata bytes. */
export function encodeTlsaRdata({ usage, selector, matchingType, data }) {
  return Buffer.concat([
    Buffer.from([usage, selector, matchingType]),
    Buffer.from(data, "hex"),
  ]);
}

/**
 * Formats a TLSA record as the presentation/storage string used by Rolodex:
 * `"usage selector matching_type hex_data"`.
 */
export function tlsaValue(record) {
  return `${record.usage} ${record.selector} ${record.matchingType} ${record.data}`;
}

function udpExchange(query, server, port, timeoutMs) {
  return new Promise((resolve, reject) => {
    const socket = dgram.createSocket("udp4");
    const timer = setTimeout(() => {
      socket.close();
      reject(new DnsError(`DNS UDP query timed out after ${timeoutMs}ms`));
    }, timeoutMs);

    const expectedId = query.readUInt16BE(0);
    socket.on("message", (msg) => {
      // Ignore stray datagrams that don't match our transaction id.
      if (msg.length >= 2 && msg.readUInt16BE(0) !== expectedId) {
        return;
      }
      clearTimeout(timer);
      socket.close();
      resolve(msg);
    });
    socket.on("error", (err) => {
      clearTimeout(timer);
      socket.close();
      reject(err);
    });
    socket.send(query, port, server, (err) => {
      if (err) {
        clearTimeout(timer);
        socket.close();
        reject(err);
      }
    });
  });
}

function tcpExchange(query, server, port, timeoutMs) {
  return new Promise((resolve, reject) => {
    const framed = Buffer.alloc(query.length + 2);
    framed.writeUInt16BE(query.length, 0);
    query.copy(framed, 2);

    const socket = net.connect({ host: server, port });
    socket.setTimeout(timeoutMs);
    let received = Buffer.alloc(0);
    let done = false;

    const fail = (err) => {
      if (done) return;
      done = true;
      socket.destroy();
      reject(err);
    };

    socket.on("timeout", () =>
      fail(new DnsError(`DNS TCP query timed out after ${timeoutMs}ms`)),
    );
    socket.on("error", fail);
    socket.on("connect", () => socket.write(framed));
    socket.on("data", (chunk) => {
      received = Buffer.concat([received, chunk]);
      if (received.length < 2) return;
      const expected = received.readUInt16BE(0);
      if (received.length >= expected + 2) {
        done = true;
        socket.end();
        resolve(received.subarray(2, expected + 2));
      }
    });
    socket.on("close", () => {
      if (!done) {
        fail(new DnsError("DNS TCP connection closed before response"));
      }
    });
  });
}

/**
 * Sends a DNS query for `name`/`type` to a server and returns the decoded
 * message. UDP is the default transport; truncated (TC) responses are
 * automatically retried over TCP. Pass `transport: "tcp"` to force TCP.
 */
export async function queryDns(name, type, opts = {}) {
  const {
    server = "127.0.0.1",
    port = 53,
    timeoutMs = 5000,
    transport = "udp",
  } = opts;

  const id = crypto.randomInt(0, 65536);
  const query = encodeQuery(name, type, id);

  let raw;
  if (transport === "tcp") {
    raw = await tcpExchange(query, server, port, timeoutMs);
  } else {
    raw = await udpExchange(query, server, port, timeoutMs);
    if (decodeMessage(raw).flags.tc) {
      raw = await tcpExchange(query, server, port, timeoutMs);
    }
  }

  const message = decodeMessage(raw);
  if (message.id !== id) {
    throw new DnsError("DNS response id mismatch");
  }
  return message;
}

/**
 * Retrieves the TLSA records for `domain` (at `_<port>._<protocol>.`) from a
 * DNS server. Returns an array of `{ usage, selector, matchingType, data }`;
 * NXDOMAIN yields an empty array, other error rcodes throw `DnsError`.
 *
 * `port`/`protocol` select the TLSA owner name (the service the records are
 * published for); `dnsServer`/`dnsPort` select the DNS endpoint to query.
 */
export async function fetchTlsaRecords(domain, opts = {}) {
  const {
    port = 443,
    protocol = "tcp",
    dnsServer = "127.0.0.1",
    dnsPort = 53,
    timeoutMs,
    transport,
  } = opts;
  const name = tlsaName(domain, port, protocol);
  const message = await queryDns(name, TLSA_TYPE, {
    server: dnsServer,
    port: dnsPort,
    ...(timeoutMs !== undefined ? { timeoutMs } : {}),
    ...(transport !== undefined ? { transport } : {}),
  });

  if (message.flags.rcode === 3) {
    return [];
  }
  if (message.flags.rcode !== 0) {
    throw new DnsError(
      `DNS query for ${name} failed with rcode ${message.flags.rcode}`,
      message.flags.rcode,
    );
  }
  return message.answers
    .filter((a) => a.type === TLSA_TYPE)
    .map((a) => parseTlsaRdata(a.rdata));
}

/** Splits concatenated PEM text into individual CERTIFICATE blocks. */
export function splitPemCertificates(pem) {
  const matches = String(pem).match(
    /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g,
  );
  return matches ? matches.map((m) => m.trim()) : [];
}

/**
 * Computes TLSA certificate association data for a PEM certificate.
 *
 * Selector 0 covers the full DER certificate; selector 1 covers the
 * SubjectPublicKeyInfo (RFC 6698 §2.1.2, matching the Rust `extract_spki`).
 * Matching type 0 is the exact data, 1 is SHA-256, 2 is SHA-512.
 * Returns lowercase hex.
 */
export function certAssociationData(certPem, selector, matchingType) {
  const cert = new crypto.X509Certificate(certPem);

  let data;
  switch (selector) {
    case 0:
      data = cert.raw;
      break;
    case 1:
      data = cert.publicKey.export({ type: "spki", format: "der" });
      break;
    default:
      throw new Error(`unsupported TLSA selector: ${selector}`);
  }

  switch (matchingType) {
    case 0:
      return data.toString("hex");
    case 1:
      return crypto.createHash("sha256").update(data).digest("hex");
    case 2:
      return crypto.createHash("sha512").update(data).digest("hex");
    default:
      throw new Error(`unsupported TLSA matching type: ${matchingType}`);
  }
}

/** Returns true when `record`'s association data matches the certificate. */
export function verifyCertAgainstTlsa(certPem, record) {
  const expected = certAssociationData(
    certPem,
    record.selector,
    record.matchingType,
  );
  const a = Buffer.from(expected, "hex");
  const b = Buffer.from(record.data, "hex");
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

/**
 * Matches retrieved TLSA records against a certificate chain (array or
 * concatenated PEM). Returns `{ record, certPem, certIndex }` for the first
 * match, or null. With Rolodex's DANE-TA publication the intermediate (chain
 * index 1 in `leaf + intermediate`) is the expected match.
 */
export function matchDane(records, chainPem) {
  const certs = Array.isArray(chainPem)
    ? chainPem
    : splitPemCertificates(chainPem);
  for (const record of records) {
    for (let i = 0; i < certs.length; i++) {
      if (verifyCertAgainstTlsa(certs[i], record)) {
        return { record, certPem: certs[i], certIndex: i };
      }
    }
  }
  return null;
}
