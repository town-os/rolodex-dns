// Integration tests for the JS client against a real rolodex-dns server.
//
// Gated on ROLODEX_DNS_BINARY (set by `make js-integration-test`). Each run
// uses a private temporary directory, random ports, and an isolated database;
// the host system is never modified.
//
// The DANE test is a cross-implementation check: the server publishes a
// DANE-TA TLSA record computed by the Rust side (x509-parser + sha2), and the
// JS client retrieves it over the DNS wire protocol (UDP and TCP) and
// independently recomputes the association data from the intermediate CA PEM
// with node:crypto. The two must agree.

import test from "node:test";
import assert from "node:assert/strict";
import { writeFileSync } from "node:fs";
import path from "node:path";

import { startServer, cli, skip } from "./server_helper.js";
import { PortalClient } from "../src/portal.js";
import {
  fetchTlsaRecords,
  certAssociationData,
  verifyCertAgainstTlsa,
  matchDane,
  splitPemCertificates,
  DnsError,
} from "../src/dane.js";

test("portal API and DANE retrieval against a live server", { skip }, async (t) => {
  const srv = await startServer(t);
  const portal = new PortalClient(`https://127.0.0.1:${srv.portalPort}`, {
    insecure: true,
  });

  let account;
  await t.test("createAccount mints a zone-scoped EAB credential", async () => {
    account = await portal.createAccount("example.com");
    assert.equal(account.zone, "example.com");
    assert.equal(account.directory_url, `https://127.0.0.1:${srv.acmePort}/acme`);
    assert.ok(account.eab_kid.length > 0);
    assert.ok(account.eab_hmac_key.length > 0);
    assert.ok(Array.isArray(account.snippets) && account.snippets.length > 0);
  });

  await t.test("listZones includes the enrolled zone", async () => {
    const zones = await portal.listZones();
    assert.ok(zones.includes("example.com"), `zones: ${zones}`);
  });

  await t.test("getCaPem returns the root CA", async () => {
    const pem = await portal.getCaPem();
    assert.match(pem, /-----BEGIN CERTIFICATE-----/);
    assert.equal(splitPemCertificates(pem).length, 1);
  });

  await t.test("listCertificates is empty before any issuance", async () => {
    assert.deepEqual(await portal.listCertificates(), []);
    assert.deepEqual(await portal.listCertificates("example.com"), []);
  });

  // --- DANE protocol retrieval ----------------------------------------------
  // The Rust side computes and publishes the DANE-TA record for the zone
  // intermediate; the JS side retrieves it via DNS and recomputes the hash.

  let rootPem;
  let intermediatePem;
  await t.test("ensure-zone-ca returns root + intermediate PEM", async () => {
    const { stdout } = await cli(srv.socketPath, [
      "ensure-zone-ca",
      "--zone",
      "example.com",
    ]);
    const certs = splitPemCertificates(stdout);
    assert.equal(certs.length, 2, `expected 2 PEM blocks in:\n${stdout}`);
    [rootPem, intermediatePem] = certs;
  });

  const domain = "dane.example.com";
  const servicePort = 8443;

  await t.test("generate-tlsa publishes a DANE-TA record (2 1 1)", async () => {
    const certPath = path.join(srv.dir, "intermediate.pem");
    writeFileSync(certPath, intermediatePem + "\n");
    const { stdout } = await cli(srv.socketPath, [
      "generate-tlsa",
      "--domain",
      domain,
      "--port",
      String(servicePort),
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
    assert.match(stdout, /2 1 1 [0-9a-f]{64}/);
  });

  const expectedSpkiSha256 = () => certAssociationData(intermediatePem, 1, 1);

  await t.test("TLSA retrieval over UDP matches the JS-computed SPKI hash", async () => {
    const records = await fetchTlsaRecords(domain, {
      port: servicePort,
      protocol: "tcp",
      dnsServer: "127.0.0.1",
      dnsPort: srv.dnsPort,
    });
    assert.equal(records.length, 1);
    assert.deepEqual(records[0], {
      usage: 2,
      selector: 1,
      matchingType: 1,
      data: expectedSpkiSha256(),
    });
  });

  await t.test("TLSA retrieval over TCP matches the UDP result", async () => {
    const records = await fetchTlsaRecords(domain, {
      port: servicePort,
      protocol: "tcp",
      dnsServer: "127.0.0.1",
      dnsPort: srv.dnsPort,
      transport: "tcp",
    });
    assert.equal(records.length, 1);
    assert.equal(records[0].data, expectedSpkiSha256());
  });

  await t.test("retrieved record verifies against the intermediate, not the root", async () => {
    const [record] = await fetchTlsaRecords(domain, {
      port: servicePort,
      protocol: "tcp",
      dnsServer: "127.0.0.1",
      dnsPort: srv.dnsPort,
    });
    assert.equal(verifyCertAgainstTlsa(intermediatePem, record), true);
    assert.equal(verifyCertAgainstTlsa(rootPem, record), false);

    // matchDane against a served chain (root + intermediate) identifies the
    // intermediate as the DANE-TA anchor.
    const match = matchDane([record], `${rootPem}\n${intermediatePem}`);
    assert.ok(match);
    assert.equal(match.certIndex, 1);
  });

  await t.test("unpublished names SERVFAIL while unforwardable", async () => {
    // No apex records exist for example.com and no forwarders are configured,
    // so an unpublished name is neither locally authoritative nor resolvable.
    await assert.rejects(
      fetchTlsaRecords("other.example.com", {
        port: servicePort,
        protocol: "tcp",
        dnsServer: "127.0.0.1",
        dnsPort: srv.dnsPort,
      }),
      (err) => err instanceof DnsError && err.rcode === 2,
    );
  });

  await t.test("unpublished names NXDOMAIN once the zone is authoritative", async () => {
    await cli(srv.socketPath, ["add-auth-zone", "--zone", "example.com"]);
    const records = await fetchTlsaRecords("other.example.com", {
      port: servicePort,
      protocol: "tcp",
      dnsServer: "127.0.0.1",
      dnsPort: srv.dnsPort,
    });
    assert.deepEqual(records, []);
  });
});
