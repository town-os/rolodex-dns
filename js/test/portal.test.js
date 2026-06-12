// Unit tests for the portal client against an in-process mock HTTPS portal
// (self-signed, like the real portal listener).

import test from "node:test";
import assert from "node:assert/strict";
import https from "node:https";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { PortalClient, PortalError } from "../src/portal.js";

const fixture = (name) =>
  readFileSync(fileURLToPath(new URL(`./fixtures/${name}`, import.meta.url)));

const CERT_PEM = fixture("cert.pem");
const KEY_PEM = fixture("key.pem");

const ROOT_CA = "-----BEGIN CERTIFICATE-----\nMOCKROOT\n-----END CERTIFICATE-----\n";

function startMockPortal() {
  const requests = [];
  const server = https.createServer({ cert: CERT_PEM, key: KEY_PEM }, (req, res) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      const body = Buffer.concat(chunks).toString("utf8");
      requests.push({ method: req.method, url: req.url, body });

      const url = new URL(req.url, "https://localhost");
      if (req.method === "GET" && url.pathname === "/api/ca") {
        res.writeHead(200, { "content-type": "application/x-pem-file" });
        res.end(ROOT_CA);
      } else if (req.method === "GET" && url.pathname === "/api/zones") {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ zones: ["example.com", "lab.home"] }));
      } else if (req.method === "GET" && url.pathname === "/api/certs") {
        const certs =
          url.searchParams.get("zone") === "empty.zone"
            ? []
            : [{ domain: "host.example.com", issued_at: 1, expires_at: 2 }];
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ certificates: certs }));
      } else if (req.method === "POST" && url.pathname === "/api/account") {
        const parsed = JSON.parse(body);
        if (!parsed.zone) {
          res.writeHead(400);
          res.end("zone is required");
          return;
        }
        res.writeHead(200, { "content-type": "application/json" });
        res.end(
          JSON.stringify({
            directory_url: "https://localhost:8555/acme",
            zone: parsed.zone,
            eab_kid: "kid-123",
            eab_hmac_key: "aGVsbG8",
            snippets: ["# lego", "# certbot"],
          }),
        );
      } else {
        res.writeHead(404);
        res.end("not found");
      }
    });
  });

  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () =>
      resolve({ server, port: server.address().port, requests }),
    );
  });
}

test("portal client end-to-end against mock portal", async (t) => {
  const { server, port, requests } = await startMockPortal();
  t.after(() => server.close());

  const client = new PortalClient(`https://127.0.0.1:${port}`, {
    insecure: true,
  });

  await t.test("getCaPem returns PEM text", async () => {
    assert.equal(await client.getCaPem(), ROOT_CA);
  });

  await t.test("listZones returns the zone list", async () => {
    assert.deepEqual(await client.listZones(), ["example.com", "lab.home"]);
  });

  await t.test("listCertificates without filter", async () => {
    const certs = await client.listCertificates();
    assert.deepEqual(certs, [
      { domain: "host.example.com", issued_at: 1, expires_at: 2 },
    ]);
  });

  await t.test("listCertificates passes the zone filter", async () => {
    assert.deepEqual(await client.listCertificates("empty.zone"), []);
    const last = requests[requests.length - 1];
    assert.equal(last.url, "/api/certs?zone=empty.zone");
  });

  await t.test("createAccount posts the zone and parses EAB", async () => {
    const account = await client.createAccount("example.com");
    assert.equal(account.eab_kid, "kid-123");
    assert.equal(account.eab_hmac_key, "aGVsbG8");
    assert.equal(account.directory_url, "https://localhost:8555/acme");
    assert.deepEqual(account.snippets, ["# lego", "# certbot"]);
    const last = requests[requests.length - 1];
    assert.equal(last.method, "POST");
    assert.equal(last.url, "/api/account");
    assert.deepEqual(JSON.parse(last.body), { zone: "example.com" });
  });

  await t.test("non-2xx responses raise PortalError with body", async () => {
    await assert.rejects(
      client.createAccount(""),
      (err) =>
        err instanceof PortalError &&
        err.status === 400 &&
        err.message.includes("zone is required"),
    );
  });

  await t.test("bare host:port base URL is treated as https", async () => {
    const bare = new PortalClient(`127.0.0.1:${port}`, { insecure: true });
    assert.deepEqual(await bare.listZones(), ["example.com", "lab.home"]);
  });

  await t.test("self-signed cert is rejected without insecure/ca", async () => {
    const strict = new PortalClient(`https://127.0.0.1:${port}`);
    await assert.rejects(strict.listZones());
  });
});
