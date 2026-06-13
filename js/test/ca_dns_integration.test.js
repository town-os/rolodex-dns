// Integration tests for CA-over-DNS distribution against a real rolodex-dns
// server with DoH enabled. Gated on ROLODEX_DNS_BINARY.
//
// This exercises the exact path the browser extension uses: the server
// publishes the root + per-zone intermediate as CERT records (RFC 4398) and
// prefixed TXT chunks when the zone CA is created, and the extension module
// retrieves them over DoH (RFC 8484 POST), preferring CERT with TXT fallback.
// Retrieved certificates are compared byte-for-byte with what the control
// plane reports, and the DANE-TA TLSA verification is run end to end.

import test from "node:test";
import assert from "node:assert/strict";
import https from "node:https";
import { writeFileSync } from "node:fs";
import path from "node:path";

import { startServer, cli, skip } from "./server_helper.js";
import { PortalClient } from "../src/portal.js";
import { splitPemCertificates, queryDns } from "../src/dane.js";
import {
  CERT_TYPE,
  TXT_TYPE,
  caCertName,
  caTxtName,
  dohQuery,
  parseCertRdata,
  parseTxtRdata,
  reassembleCaTxt,
  fetchCaChain,
  verifyDaneTa,
  isSelfSigned,
  bytesToBase64,
} from "../../extension/ca_dns.js";

/**
 * A fetch-compatible function over node:https that skips TLS verification —
 * the DoH listener serves an auto-generated self-signed certificate. Only
 * used inside this test; injected via the module's `fetchFn` option.
 */
function insecureFetch(url, opts = {}) {
  return new Promise((resolve, reject) => {
    const req = https.request(
      new URL(url),
      {
        method: opts.method ?? "GET",
        headers: opts.headers ?? {},
        rejectUnauthorized: false,
      },
      (res) => {
        const chunks = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => {
          const body = Buffer.concat(chunks);
          resolve({
            ok: res.statusCode >= 200 && res.statusCode < 300,
            status: res.statusCode,
            arrayBuffer: async () =>
              body.buffer.slice(body.byteOffset, body.byteOffset + body.byteLength),
          });
        });
      },
    );
    req.on("error", reject);
    if (opts.body) {
      req.write(Buffer.from(opts.body));
    }
    req.end();
  });
}

const pemBody = (pem) =>
  pem
    .split("\n")
    .filter((l) => l && !l.startsWith("-----"))
    .join("");

test("CA retrieval over DNS against a live server", { skip }, async (t) => {
  const srv = await startServer(t, { doh: true });
  const dohUrl = `https://127.0.0.1:${srv.dohPort}/dns-query`;
  const portal = new PortalClient(`https://127.0.0.1:${srv.portalPort}`, {
    insecure: true,
  });

  // Creating the zone CA (via the portal, as a browser user would) must
  // publish the CA records into DNS.
  await portal.createAccount("example.com");

  // Reference PEMs from the control plane.
  const { stdout } = await cli(srv.socketPath, [
    "ensure-zone-ca",
    "--zone",
    "example.com",
  ]);
  const [rootPem, intermediatePem] = splitPemCertificates(stdout);
  assert.ok(rootPem && intermediatePem, "ensure-zone-ca returns both PEMs");

  await t.test("extension retrieves the chain via CERT records over DoH", async () => {
    const chain = await fetchCaChain(dohUrl, "example.com", {
      fetchFn: insecureFetch,
    });
    assert.equal(chain.source, "cert");
    assert.equal(bytesToBase64(chain.root.der), pemBody(rootPem));
    assert.equal(bytesToBase64(chain.intermediate.der), pemBody(intermediatePem));
    assert.equal(isSelfSigned(chain.root.der), true);
    assert.equal(isSelfSigned(chain.intermediate.der), false);
  });

  await t.test("root CA from DNS matches the portal download", async () => {
    const chain = await fetchCaChain(dohUrl, "example.com", {
      fetchFn: insecureFetch,
    });
    const portalRoot = await portal.getCaPem();
    assert.equal(bytesToBase64(chain.root.der), pemBody(portalRoot));
  });

  await t.test("TXT fallback records reassemble to the same chain", async () => {
    const msg = await dohQuery(dohUrl, caTxtName("example.com"), TXT_TYPE, {
      fetchFn: insecureFetch,
    });
    assert.equal(msg.flags.rcode, 0);
    const strings = msg.answers
      .filter((a) => a.type === TXT_TYPE)
      .flatMap((a) => parseTxtRdata(a.rdata));
    const kinds = reassembleCaTxt(strings);
    assert.equal(bytesToBase64(kinds.root), pemBody(rootPem));
    assert.equal(bytesToBase64(kinds.intermediate), pemBody(intermediatePem));
  });

  await t.test("CERT records are also served over plain DNS (UDP)", async () => {
    // The same records must be retrievable by any DNS client, not just DoH —
    // query over UDP with the Node client codec and parse with the
    // extension's CERT parser.
    const msg = await queryDns(caCertName("example.com"), CERT_TYPE, {
      server: "127.0.0.1",
      port: srv.dnsPort,
    });
    assert.equal(msg.flags.rcode, 0);
    const ders = msg.answers
      .filter((a) => a.type === CERT_TYPE)
      .map((a) => parseCertRdata(new Uint8Array(a.rdata)))
      .filter((c) => c.certType === 1)
      .map((c) => c.certData);
    assert.equal(ders.length, 2);
    const payloads = ders.map(bytesToBase64).sort();
    const expected = [pemBody(rootPem), pemBody(intermediatePem)].sort();
    assert.deepEqual(payloads, expected);
  });

  await t.test("retrieved intermediate verifies via DANE-TA over DoH", async () => {
    // Publish the DANE-TA record for a host the way the issuer does.
    const certPath = path.join(srv.dir, "intermediate.pem");
    writeFileSync(certPath, intermediatePem + "\n");
    await cli(srv.socketPath, [
      "generate-tlsa",
      "--domain",
      "host.example.com",
      "--port",
      "443",
      "--protocol",
      "tcp",
      "--cert-path",
      certPath,
      "--usage",
      "2",
      "--selector",
      "1",
      "--matching-type",
      "1",
    ]);

    const chain = await fetchCaChain(dohUrl, "example.com", {
      fetchFn: insecureFetch,
    });
    const ok = await verifyDaneTa(dohUrl, "host.example.com", chain.intermediate.der, {
      fetchFn: insecureFetch,
    });
    assert.equal(ok.records.length, 1);
    assert.equal(ok.verified, true);

    // The root must NOT match the DANE-TA record (it pins the intermediate).
    const bad = await verifyDaneTa(dohUrl, "host.example.com", chain.root.der, {
      fetchFn: insecureFetch,
    });
    assert.equal(bad.verified, false);
  });
});
