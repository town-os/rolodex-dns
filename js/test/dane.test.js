// Unit tests for the DANE/TLSA module: DNS wire codec, TLSA retrieval over
// UDP and TCP (against in-process mock DNS servers), and certificate
// association data computed against an openssl-generated fixture with
// openssl-computed expected hashes (an oracle independent of node:crypto).

import test from "node:test";
import assert from "node:assert/strict";
import dgram from "node:dgram";
import net from "node:net";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import {
  TLSA_TYPE,
  tlsaName,
  tlsaValue,
  encodeName,
  decodeName,
  encodeResponse,
  decodeMessage,
  parseTlsaRdata,
  encodeTlsaRdata,
  queryDns,
  fetchTlsaRecords,
  splitPemCertificates,
  certAssociationData,
  verifyCertAgainstTlsa,
  matchDane,
  DnsError,
} from "../src/dane.js";

const fixture = (name) =>
  readFileSync(fileURLToPath(new URL(`./fixtures/${name}`, import.meta.url)));

const CERT_PEM = fixture("cert.pem").toString("utf8");
const EXPECTED = JSON.parse(fixture("expected.json").toString("utf8"));

test("tlsaName formats _port._proto.domain.", () => {
  assert.equal(tlsaName("example.com", 443, "tcp"), "_443._tcp.example.com.");
  assert.equal(tlsaName("example.com.", 443, "tcp"), "_443._tcp.example.com.");
  assert.equal(
    tlsaName("mail.example.com", 25, "tcp"),
    "_25._tcp.mail.example.com.",
  );
  assert.equal(tlsaName("example.com", 8853, "udp"), "_8853._udp.example.com.");
});

test("encodeName/decodeName round-trip", () => {
  const buf = encodeName("_443._tcp.example.com.");
  const { name, next } = decodeName(buf, 0);
  assert.equal(name, "_443._tcp.example.com.");
  assert.equal(next, buf.length);
});

test("decodeName follows compression pointers", () => {
  // Hand-built message fragment: "example.com." at offset 2, then a name
  // "www" + pointer to offset 2.
  const target = encodeName("example.com.");
  const prefix = Buffer.from([0, 0]);
  const www = Buffer.concat([
    Buffer.from([3]),
    Buffer.from("www", "ascii"),
    Buffer.from([0xc0, 0x02]),
  ]);
  const buf = Buffer.concat([prefix, target, www]);
  const offset = prefix.length + target.length;
  const { name, next } = decodeName(buf, offset);
  assert.equal(name, "www.example.com.");
  assert.equal(next, buf.length);
});

test("decodeName rejects pointer loops", () => {
  // A pointer at offset 0 pointing to itself.
  const buf = Buffer.from([0xc0, 0x00]);
  assert.throws(() => decodeName(buf, 0), DnsError);
});

test("query/response codec round-trip with TLSA answer", () => {
  const record = {
    usage: 2,
    selector: 1,
    matchingType: 1,
    data: EXPECTED.spkiSha256,
  };
  const response = encodeResponse({
    id: 0x1234,
    question: { name: "_443._tcp.example.com.", type: TLSA_TYPE },
    answers: [
      {
        name: "_443._tcp.example.com.",
        type: TLSA_TYPE,
        ttl: 3600,
        rdata: encodeTlsaRdata(record),
      },
    ],
  });
  const decoded = decodeMessage(response);
  assert.equal(decoded.id, 0x1234);
  assert.equal(decoded.flags.qr, true);
  assert.equal(decoded.flags.rcode, 0);
  assert.equal(decoded.questions.length, 1);
  assert.equal(decoded.questions[0].name, "_443._tcp.example.com.");
  assert.equal(decoded.answers.length, 1);
  assert.equal(decoded.answers[0].ttl, 3600);
  const parsed = parseTlsaRdata(decoded.answers[0].rdata);
  assert.deepEqual(parsed, record);
  assert.equal(tlsaValue(parsed), `2 1 1 ${EXPECTED.spkiSha256}`);
});

test("parseTlsaRdata rejects short rdata", () => {
  assert.throws(() => parseTlsaRdata(Buffer.from([2, 1])), DnsError);
});

// --- mock DNS servers -------------------------------------------------------

const RECORD = {
  usage: 2,
  selector: 1,
  matchingType: 1,
  data: EXPECTED.spkiSha256,
};

function tlsaAnswerFor(query, { flags = 0x8180, answers = null } = {}) {
  const q = decodeMessage(query);
  return encodeResponse({
    id: q.id,
    flags,
    question: q.questions[0],
    answers:
      answers ??
      [
        {
          name: q.questions[0].name,
          type: TLSA_TYPE,
          ttl: 300,
          rdata: encodeTlsaRdata(RECORD),
        },
      ],
  });
}

function startUdpDns(handler) {
  return new Promise((resolve) => {
    const socket = dgram.createSocket("udp4");
    socket.on("message", (msg, rinfo) => {
      const reply = handler(msg);
      if (reply) socket.send(reply, rinfo.port, rinfo.address);
    });
    socket.bind(0, "127.0.0.1", () =>
      resolve({ socket, port: socket.address().port }),
    );
  });
}

function startTcpDns(handler) {
  return new Promise((resolve) => {
    const server = net.createServer((conn) => {
      let buf = Buffer.alloc(0);
      conn.on("data", (chunk) => {
        buf = Buffer.concat([buf, chunk]);
        if (buf.length < 2) return;
        const len = buf.readUInt16BE(0);
        if (buf.length < len + 2) return;
        const reply = handler(buf.subarray(2, len + 2));
        const framed = Buffer.alloc(reply.length + 2);
        framed.writeUInt16BE(reply.length, 0);
        reply.copy(framed, 2);
        conn.write(framed);
      });
    });
    server.listen(0, "127.0.0.1", () =>
      resolve({ server, port: server.address().port }),
    );
  });
}

test("fetchTlsaRecords over UDP", async () => {
  const { socket, port } = await startUdpDns((q) => tlsaAnswerFor(q));
  try {
    const records = await fetchTlsaRecords("example.com", {
      port: 443,
      protocol: "tcp",
      dnsServer: "127.0.0.1",
      dnsPort: port,
    });
    assert.deepEqual(records, [RECORD]);
  } finally {
    socket.close();
  }
});

test("fetchTlsaRecords over TCP", async () => {
  const { server, port } = await startTcpDns((q) => tlsaAnswerFor(q));
  try {
    const records = await fetchTlsaRecords("example.com", {
      dnsServer: "127.0.0.1",
      dnsPort: port,
      transport: "tcp",
    });
    assert.deepEqual(records, [RECORD]);
  } finally {
    server.close();
  }
});

test("truncated UDP response falls back to TCP", async () => {
  // UDP answers with TC set and no answers; TCP must be consulted and the
  // same port is used for both transports.
  const tcp = await startTcpDns((q) => tlsaAnswerFor(q));
  // Bind UDP on the same port number as the TCP listener.
  const udpSocket = dgram.createSocket("udp4");
  await new Promise((resolve, reject) => {
    udpSocket.once("error", reject);
    udpSocket.bind(tcp.port, "127.0.0.1", resolve);
  });
  udpSocket.on("message", (msg, rinfo) => {
    const reply = tlsaAnswerFor(msg, { flags: 0x8380, answers: [] }); // TC set
    udpSocket.send(reply, rinfo.port, rinfo.address);
  });

  try {
    const records = await fetchTlsaRecords("example.com", {
      dnsServer: "127.0.0.1",
      dnsPort: tcp.port,
    });
    assert.deepEqual(records, [RECORD]);
  } finally {
    udpSocket.close();
    tcp.server.close();
  }
});

test("NXDOMAIN yields an empty record set", async () => {
  const { socket, port } = await startUdpDns((q) =>
    tlsaAnswerFor(q, { flags: 0x8183, answers: [] }),
  );
  try {
    const records = await fetchTlsaRecords("missing.example.com", {
      dnsServer: "127.0.0.1",
      dnsPort: port,
    });
    assert.deepEqual(records, []);
  } finally {
    socket.close();
  }
});

test("SERVFAIL raises DnsError with rcode", async () => {
  const { socket, port } = await startUdpDns((q) =>
    tlsaAnswerFor(q, { flags: 0x8182, answers: [] }),
  );
  try {
    await assert.rejects(
      fetchTlsaRecords("example.com", {
        dnsServer: "127.0.0.1",
        dnsPort: port,
      }),
      (err) => err instanceof DnsError && err.rcode === 2,
    );
  } finally {
    socket.close();
  }
});

test("UDP query times out without a response", async () => {
  const { socket, port } = await startUdpDns(() => null);
  try {
    await assert.rejects(
      queryDns("example.com.", TLSA_TYPE, {
        server: "127.0.0.1",
        port,
        timeoutMs: 200,
      }),
      DnsError,
    );
  } finally {
    socket.close();
  }
});

// --- certificate association data vs. openssl oracle ------------------------

test("selector 1 / matching 1 equals openssl SPKI sha256", () => {
  assert.equal(certAssociationData(CERT_PEM, 1, 1), EXPECTED.spkiSha256);
});

test("selector 1 / matching 2 equals openssl SPKI sha512", () => {
  assert.equal(certAssociationData(CERT_PEM, 1, 2), EXPECTED.spkiSha512);
});

test("selector 1 / matching 0 equals openssl SPKI DER", () => {
  assert.equal(certAssociationData(CERT_PEM, 1, 0), EXPECTED.spkiHex);
});

test("selector 0 / matching 1 equals openssl full-cert sha256", () => {
  assert.equal(certAssociationData(CERT_PEM, 0, 1), EXPECTED.certSha256);
});

test("unsupported selector/matching type throw", () => {
  assert.throws(() => certAssociationData(CERT_PEM, 7, 1));
  assert.throws(() => certAssociationData(CERT_PEM, 1, 7));
});

test("verifyCertAgainstTlsa accepts a matching DANE-TA record", () => {
  assert.equal(verifyCertAgainstTlsa(CERT_PEM, RECORD), true);
});

test("verifyCertAgainstTlsa rejects a tampered record", () => {
  const tampered = {
    ...RECORD,
    data: RECORD.data.replace(/^../, RECORD.data.startsWith("00") ? "ff" : "00"),
  };
  assert.equal(verifyCertAgainstTlsa(CERT_PEM, tampered), false);
});

test("matchDane finds the matching certificate in a chain", () => {
  const chain = `${CERT_PEM}\n${CERT_PEM}`;
  assert.equal(splitPemCertificates(chain).length, 2);
  const match = matchDane([RECORD], chain);
  assert.ok(match);
  assert.equal(match.certIndex, 0);
  assert.equal(match.record, RECORD);
  assert.equal(matchDane([{ ...RECORD, data: "00".repeat(32) }], chain), null);
});
