// Unit tests for the browser extension's CA-over-DNS module
// (extension/ca_dns.js). The module is browser-targeted (Uint8Array,
// WebCrypto, atob/btoa) but runs unmodified under Node 20, so it is tested
// here with the Node test runner.
//
// Wire-format interop is cross-checked against the Node client codec in
// js/src/dane.js: responses are built with the Buffer-based encoder and
// parsed with the extension's Uint8Array-based decoder. Certificate parsing
// is checked against openssl-generated fixtures with openssl-computed
// expected hashes.

import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import crypto from "node:crypto";

import {
  CERT_TYPE,
  TXT_TYPE,
  TLSA_TYPE,
  CA_TXT_PREFIX,
  caCertName,
  caTxtName,
  tlsaName,
  encodeQuery,
  decodeMessage,
  parseCertRdata,
  parseTxtRdata,
  parseTlsaRdata,
  base64ToBytes,
  bytesToBase64,
  derToPem,
  parseCertificateFields,
  isSelfSigned,
  spkiSha256Hex,
  reassembleCaTxt,
  fetchCaChain,
  verifyDaneTa,
  dohQuery,
} from "../../extension/ca_dns.js";

import { encodeResponse, encodeTlsaRdata } from "../src/dane.js";

const fixture = (name) =>
  readFileSync(fileURLToPath(new URL(`./fixtures/${name}`, import.meta.url)));

const ROOT_PEM = fixture("cert.pem").toString("utf8");
const INTERMEDIATE_PEM = fixture("intermediate.pem").toString("utf8");
const EXPECTED = JSON.parse(fixture("expected.json").toString("utf8"));

const pemBody = (pem) =>
  pem
    .split("\n")
    .filter((l) => l && !l.startsWith("-----"))
    .join("");

const ROOT_DER = base64ToBytes(pemBody(ROOT_PEM));
const INT_DER = base64ToBytes(pemBody(INTERMEDIATE_PEM));

/** Builds CERT rdata (RFC 4398) for a DER payload. */
function certRdata(der, certType = 1) {
  const out = Buffer.alloc(5 + der.length);
  out.writeUInt16BE(certType, 0);
  out.writeUInt16BE(0, 2); // key tag
  out.writeUInt8(0, 4); // algorithm
  Buffer.from(der).copy(out, 5);
  return out;
}

/** Builds TXT rdata from one character-string. */
function txtRdata(s) {
  const bytes = Buffer.from(s, "ascii");
  return Buffer.concat([Buffer.from([bytes.length]), bytes]);
}

/** Splits a base64 string into framed rolodex-ca TXT values. */
function caTxtValues(kind, b64, chunkSize = 180) {
  const chunks = [];
  for (let i = 0; i < b64.length; i += chunkSize) {
    chunks.push(b64.slice(i, i + chunkSize));
  }
  return chunks.map(
    (c, i) => `${CA_TXT_PREFIX}:${kind}:${i + 1}/${chunks.length}:${c}`,
  );
}

/** A fetchFn that answers DoH POSTs from a name/type-keyed response table. */
function mockDoh(handler) {
  return async (_url, opts) => {
    const query = decodeMessage(new Uint8Array(opts.body));
    const q = query.questions[0];
    const { flags = 0x8180, answers = [] } = handler(q) ?? {};
    const body = encodeResponse({
      id: query.id,
      flags,
      question: q,
      answers,
    });
    return {
      ok: true,
      status: 200,
      arrayBuffer: async () =>
        body.buffer.slice(body.byteOffset, body.byteOffset + body.byteLength),
    };
  };
}

test("owner name construction", () => {
  assert.equal(caCertName("example.com"), "_ca.example.com.");
  assert.equal(caCertName("example.com."), "_ca.example.com.");
  assert.equal(caTxtName("example.com"), "_rolodex-ca.example.com.");
  assert.equal(tlsaName("host.example.com", 443, "tcp"), "_443._tcp.host.example.com.");
});

test("extension decoder parses Node-encoded responses (codec interop)", () => {
  const id = 0x4242;
  const query = encodeQuery("_ca.example.com.", CERT_TYPE, id);
  const decodedQuery = decodeMessage(query);
  assert.equal(decodedQuery.id, id);
  assert.equal(decodedQuery.questions[0].name, "_ca.example.com.");
  assert.equal(decodedQuery.questions[0].type, CERT_TYPE);

  const response = encodeResponse({
    id,
    question: { name: "_ca.example.com.", type: CERT_TYPE },
    answers: [
      { name: "_ca.example.com.", type: CERT_TYPE, ttl: 3600, rdata: certRdata(ROOT_DER) },
    ],
  });
  const decoded = decodeMessage(new Uint8Array(response));
  assert.equal(decoded.answers.length, 1);
  const cert = parseCertRdata(decoded.answers[0].rdata);
  assert.equal(cert.certType, 1);
  assert.equal(cert.keyTag, 0);
  assert.equal(cert.algorithm, 0);
  assert.deepEqual(Array.from(cert.certData), Array.from(ROOT_DER));
});

test("parseTxtRdata handles multiple character-strings", () => {
  const rdata = Buffer.concat([txtRdata("hello"), txtRdata("world")]);
  assert.deepEqual(parseTxtRdata(new Uint8Array(rdata)), ["hello", "world"]);
});

test("parseTlsaRdata round-trips against the Node encoder", () => {
  const rec = { usage: 2, selector: 1, matchingType: 1, data: "ab".repeat(32) };
  const parsed = parseTlsaRdata(new Uint8Array(encodeTlsaRdata(rec)));
  assert.deepEqual(parsed, rec);
});

test("base64 helpers round-trip and derToPem matches openssl framing", () => {
  const bytes = new Uint8Array([0, 1, 2, 250, 251, 252]);
  assert.deepEqual(Array.from(base64ToBytes(bytesToBase64(bytes))), Array.from(bytes));

  // derToPem(root DER) must reproduce the original openssl PEM exactly
  // (modulo line endings).
  assert.equal(derToPem(ROOT_DER).replace(/\n/g, ""), ROOT_PEM.replace(/\n/g, ""));
});

test("parseCertificateFields extracts the SPKI node:crypto agrees with", () => {
  const { spki } = parseCertificateFields(ROOT_DER);
  const nodeSpki = new crypto.X509Certificate(ROOT_PEM).publicKey.export({
    type: "spki",
    format: "der",
  });
  assert.deepEqual(Array.from(spki), Array.from(new Uint8Array(nodeSpki)));
});

test("isSelfSigned distinguishes root from intermediate", () => {
  assert.equal(isSelfSigned(ROOT_DER), true);
  assert.equal(isSelfSigned(INT_DER), false);
});

test("spkiSha256Hex matches the openssl oracle", async () => {
  assert.equal(await spkiSha256Hex(ROOT_DER), EXPECTED.spkiSha256);
  assert.equal(await spkiSha256Hex(INT_DER), EXPECTED.intermediateSpkiSha256);
});

test("reassembleCaTxt reorders chunks and ignores foreign TXT data", () => {
  const b64 = pemBody(ROOT_PEM);
  const values = caTxtValues("root", b64, 50);
  // Shuffle deterministically and mix in unrelated TXT strings.
  const shuffled = [...values].reverse();
  shuffled.splice(1, 0, "v=spf1 -all", "some other txt");
  const out = reassembleCaTxt(shuffled);
  assert.deepEqual(Array.from(out.root), Array.from(ROOT_DER));
});

test("reassembleCaTxt rejects incomplete chunk sets", () => {
  const values = caTxtValues("root", pemBody(ROOT_PEM), 50);
  values.pop();
  assert.throws(() => reassembleCaTxt(values), /incomplete root CA/);
});

test("fetchCaChain prefers CERT records", async () => {
  const fetchFn = mockDoh((q) => {
    assert.equal(q.name, "_ca.example.com.");
    assert.equal(q.type, CERT_TYPE);
    return {
      answers: [
        { name: q.name, type: CERT_TYPE, ttl: 3600, rdata: certRdata(INT_DER) },
        { name: q.name, type: CERT_TYPE, ttl: 3600, rdata: certRdata(ROOT_DER) },
      ],
    };
  });
  const chain = await fetchCaChain("https://doh.test/dns-query", "example.com", { fetchFn });
  assert.equal(chain.source, "cert");
  assert.deepEqual(Array.from(chain.root.der), Array.from(ROOT_DER));
  assert.deepEqual(Array.from(chain.intermediate.der), Array.from(INT_DER));
  assert.match(chain.root.pem, /BEGIN CERTIFICATE/);
});

test("fetchCaChain ignores non-PKIX CERT records", async () => {
  const queried = [];
  const fetchFn = mockDoh((q) => {
    queried.push(q.name);
    if (q.type === CERT_TYPE) {
      // A CERT record of type 2 (SPKI) must not be treated as an X.509 cert.
      return {
        answers: [
          { name: q.name, type: CERT_TYPE, ttl: 3600, rdata: certRdata(ROOT_DER, 2) },
        ],
      };
    }
    return {
      answers: [
        ...caTxtValues("root", pemBody(ROOT_PEM)),
        ...caTxtValues("intermediate", pemBody(INTERMEDIATE_PEM)),
      ].map((v) => ({ name: q.name, type: TXT_TYPE, ttl: 3600, rdata: txtRdata(v) })),
    };
  });
  const chain = await fetchCaChain("https://doh.test/dns-query", "example.com", { fetchFn });
  assert.equal(chain.source, "txt");
  assert.deepEqual(queried, ["_ca.example.com.", "_rolodex-ca.example.com."]);
});

test("fetchCaChain falls back to TXT on NXDOMAIN for CERT", async () => {
  const fetchFn = mockDoh((q) => {
    if (q.type === CERT_TYPE) {
      return { flags: 0x8183, answers: [] }; // NXDOMAIN
    }
    assert.equal(q.name, "_rolodex-ca.example.com.");
    return {
      answers: [
        ...caTxtValues("root", pemBody(ROOT_PEM)),
        ...caTxtValues("intermediate", pemBody(INTERMEDIATE_PEM)),
      ].map((v) => ({ name: q.name, type: TXT_TYPE, ttl: 3600, rdata: txtRdata(v) })),
    };
  });
  const chain = await fetchCaChain("https://doh.test/dns-query", "example.com", { fetchFn });
  assert.equal(chain.source, "txt");
  assert.deepEqual(Array.from(chain.root.der), Array.from(ROOT_DER));
  assert.deepEqual(Array.from(chain.intermediate.der), Array.from(INT_DER));
});

test("fetchCaChain falls back to TXT when the CERT query throws", async () => {
  let first = true;
  const txtFetch = mockDoh((q) => ({
    answers: [
      ...caTxtValues("root", pemBody(ROOT_PEM)),
      ...caTxtValues("intermediate", pemBody(INTERMEDIATE_PEM)),
    ].map((v) => ({ name: q.name, type: TXT_TYPE, ttl: 3600, rdata: txtRdata(v) })),
  }));
  const fetchFn = async (url, opts) => {
    if (first) {
      first = false;
      throw new Error("connection refused");
    }
    return txtFetch(url, opts);
  };
  const chain = await fetchCaChain("https://doh.test/dns-query", "example.com", { fetchFn });
  assert.equal(chain.source, "txt");
});

test("fetchCaChain errors when nothing is published", async () => {
  const fetchFn = mockDoh(() => ({ flags: 0x8183, answers: [] }));
  await assert.rejects(
    fetchCaChain("https://doh.test/dns-query", "example.com", { fetchFn }),
    /CA TXT lookup failed|no CA published/,
  );
});

test("verifyDaneTa confirms a matching intermediate", async () => {
  const spki = await spkiSha256Hex(INT_DER);
  const fetchFn = mockDoh((q) => {
    assert.equal(q.name, "_443._tcp.host.example.com.");
    assert.equal(q.type, TLSA_TYPE);
    return {
      answers: [
        {
          name: q.name,
          type: TLSA_TYPE,
          ttl: 3600,
          rdata: encodeTlsaRdata({ usage: 2, selector: 1, matchingType: 1, data: spki }),
        },
      ],
    };
  });
  const { records, verified } = await verifyDaneTa(
    "https://doh.test/dns-query",
    "host.example.com",
    INT_DER,
    { fetchFn },
  );
  assert.equal(records.length, 1);
  assert.equal(verified, true);
});

test("verifyDaneTa rejects a non-matching certificate", async () => {
  const spki = await spkiSha256Hex(INT_DER);
  const fetchFn = mockDoh((q) => ({
    answers: [
      {
        name: q.name,
        type: TLSA_TYPE,
        ttl: 3600,
        rdata: encodeTlsaRdata({ usage: 2, selector: 1, matchingType: 1, data: spki }),
      },
    ],
  }));
  const { verified } = await verifyDaneTa(
    "https://doh.test/dns-query",
    "host.example.com",
    ROOT_DER, // wrong certificate
    { fetchFn },
  );
  assert.equal(verified, false);
});

test("verifyDaneTa yields null when no TLSA records exist", async () => {
  const fetchFn = mockDoh(() => ({ flags: 0x8183, answers: [] }));
  const { records, verified } = await verifyDaneTa(
    "https://doh.test/dns-query",
    "host.example.com",
    INT_DER,
    { fetchFn },
  );
  assert.deepEqual(records, []);
  assert.equal(verified, null);
});

test("dohQuery rejects non-2xx responses and id mismatches", async () => {
  await assert.rejects(
    dohQuery("https://doh.test/dns-query", "example.com.", TXT_TYPE, {
      fetchFn: async () => ({ ok: false, status: 502, arrayBuffer: async () => new ArrayBuffer(0) }),
    }),
    /HTTP 502/,
  );

  const wrongId = async (_url, _opts) => {
    const body = encodeResponse({
      id: 1, // never matches the random query id
      question: { name: "example.com.", type: TXT_TYPE },
      answers: [],
    });
    return {
      ok: true,
      status: 200,
      arrayBuffer: async () =>
        body.buffer.slice(body.byteOffset, body.byteOffset + body.byteLength),
    };
  };
  await assert.rejects(
    dohQuery("https://doh.test/dns-query", "example.com.", TXT_TYPE, { fetchFn: wrongId }),
    /id mismatch/,
  );
});
