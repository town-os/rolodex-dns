// Unit tests for the local UI server: portal proxying (over self-signed TLS)
// and the browser-facing DANE lookup endpoint, backed by a mock HTTPS portal
// and a mock UDP DNS server.

import test from "node:test";
import assert from "node:assert/strict";
import https from "node:https";
import dgram from "node:dgram";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { createUiServer } from "../src/ui_server.js";
import {
  TLSA_TYPE,
  decodeMessage,
  encodeResponse,
  encodeTlsaRdata,
  certAssociationData,
} from "../src/dane.js";

const fixture = (name) =>
  readFileSync(fileURLToPath(new URL(`./fixtures/${name}`, import.meta.url)));

const CERT_PEM = fixture("cert.pem");
const KEY_PEM = fixture("key.pem");
const SPKI_SHA256 = certAssociationData(CERT_PEM.toString("utf8"), 1, 1);

function startMockPortal() {
  const server = https.createServer({ cert: CERT_PEM, key: KEY_PEM }, (req, res) => {
    const url = new URL(req.url, "https://localhost");
    if (req.method === "GET" && url.pathname === "/api/zones") {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ zones: ["example.com"] }));
    } else if (req.method === "GET" && url.pathname === "/api/certs") {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ certificates: [] }));
    } else if (req.method === "GET" && url.pathname === "/api/ca") {
      res.writeHead(200, { "content-type": "application/x-pem-file" });
      res.end(CERT_PEM);
    } else if (req.method === "POST" && url.pathname === "/api/account") {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(
        JSON.stringify({
          directory_url: "https://localhost:8555/acme",
          zone: "example.com",
          eab_kid: "kid-ui",
          eab_hmac_key: "aGVsbG8",
          snippets: [],
        }),
      );
    } else {
      res.writeHead(404);
      res.end();
    }
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () =>
      resolve({ server, port: server.address().port }),
    );
  });
}

function startMockDns() {
  return new Promise((resolve) => {
    const socket = dgram.createSocket("udp4");
    socket.on("message", (msg, rinfo) => {
      const q = decodeMessage(msg);
      const reply = encodeResponse({
        id: q.id,
        question: q.questions[0],
        answers: [
          {
            name: q.questions[0].name,
            type: TLSA_TYPE,
            ttl: 300,
            rdata: encodeTlsaRdata({
              usage: 2,
              selector: 1,
              matchingType: 1,
              data: SPKI_SHA256,
            }),
          },
        ],
      });
      socket.send(reply, rinfo.port, rinfo.address);
    });
    socket.bind(0, "127.0.0.1", () =>
      resolve({ socket, port: socket.address().port }),
    );
  });
}

test("ui server", async (t) => {
  const portal = await startMockPortal();
  const dns = await startMockDns();
  const ui = createUiServer({
    portalUrl: `https://127.0.0.1:${portal.port}`,
    insecure: true,
    dnsServer: "127.0.0.1",
    dnsPort: dns.port,
  });
  await new Promise((resolve) => ui.listen(0, "127.0.0.1", resolve));
  const base = `http://127.0.0.1:${ui.address().port}`;

  t.after(() => {
    ui.close();
    portal.server.close();
    dns.socket.close();
  });

  await t.test("serves the UI page", async () => {
    const res = await fetch(`${base}/`);
    assert.equal(res.status, 200);
    const html = await res.text();
    assert.match(html, /DANE \/ TLSA lookup/);
    assert.match(html, /Rolodex CA/);
  });

  await t.test("proxies /api/zones", async () => {
    const res = await fetch(`${base}/api/zones`);
    assert.equal(res.status, 200);
    assert.deepEqual(await res.json(), { zones: ["example.com"] });
  });

  await t.test("proxies /api/certs", async () => {
    const res = await fetch(`${base}/api/certs`);
    assert.deepEqual(await res.json(), { certificates: [] });
  });

  await t.test("proxies /api/ca as a PEM download", async () => {
    const res = await fetch(`${base}/api/ca`);
    assert.equal(res.headers.get("content-type"), "application/x-pem-file");
    assert.match(await res.text(), /BEGIN CERTIFICATE/);
  });

  await t.test("proxies /api/account", async () => {
    const res = await fetch(`${base}/api/account`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ zone: "example.com" }),
    });
    const body = await res.json();
    assert.equal(body.eab_kid, "kid-ui");
  });

  await t.test("rejects /api/account without a zone", async () => {
    const res = await fetch(`${base}/api/account`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({}),
    });
    assert.equal(res.status, 400);
  });

  await t.test("DANE lookup retrieves and verifies TLSA records", async () => {
    const res = await fetch(`${base}/api/dane`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        domain: "host.example.com",
        port: 443,
        protocol: "tcp",
        certPem: CERT_PEM.toString("utf8"),
      }),
    });
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.name, "_443._tcp.host.example.com.");
    assert.equal(body.records.length, 1);
    assert.equal(body.records[0].value, `2 1 1 ${SPKI_SHA256}`);
    assert.equal(body.verified, true);
    assert.equal(body.matchedIndex, 0);
  });

  await t.test("DANE lookup reports a non-matching certificate", async () => {
    const res = await fetch(`${base}/api/dane`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        domain: "host.example.com",
        certPem: fixture("cert2.pem").toString("utf8"),
      }),
    });
    const body = await res.json();
    assert.equal(body.verified, false);
    assert.equal(body.matchedIndex, null);
  });

  await t.test("DANE lookup without a PEM skips verification", async () => {
    const res = await fetch(`${base}/api/dane`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ domain: "host.example.com" }),
    });
    const body = await res.json();
    assert.equal(body.verified, null);
    assert.equal(body.matchedIndex, null);
  });

  await t.test("rejects DANE lookup without a domain", async () => {
    const res = await fetch(`${base}/api/dane`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({}),
    });
    assert.equal(res.status, 400);
  });

  await t.test("unknown paths return 404", async () => {
    const res = await fetch(`${base}/api/nope`);
    assert.equal(res.status, 404);
  });
});
