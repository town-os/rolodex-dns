# rolodex-ca-client

JavaScript client for the Rolodex DNS ACME issuer. Three pieces:

- **`PortalClient`** — the trusted-network enrollment portal JSON API
  (`/api/account`, `/api/ca`, `/api/zones`, `/api/certs`): mint zone-scoped
  EAB credentials, download the root CA, list zones and issued certificates.
- **DANE helpers** — TLSA retrieval over the DNS wire protocol (UDP with
  automatic TCP fallback on truncation) and verification of records against
  PEM certificates, independent of the server that published them.
- **`rolodex-ca-ui`** — a local web console that proxies the portal (absorbing
  its self-signed TLS) and adds browser-accessible DANE lookups.

Requires Node 20+. The library has no runtime dependencies; `npm install`
(or `make deps` from the repo root) pulls in eslint for development.

## Portal API

```js
import { PortalClient } from "rolodex-ca-client";

const portal = new PortalClient("https://127.0.0.1:8500", {
  // the portal listener uses an auto-generated self-signed cert by default;
  // pass its cert via `ca`, or `insecure: true` on the trusted network.
  insecure: true,
});

const account = await portal.createAccount("example.com");
// { directory_url, zone, eab_kid, eab_hmac_key, snippets }

const zones = await portal.listZones();        // ["example.com", ...]
const rootCa = await portal.getCaPem();        // PEM text
const certs = await portal.listCertificates(); // [{ domain, issued_at, expires_at }]
```

## DANE / TLSA retrieval

```js
import {
  fetchTlsaRecords,
  verifyCertAgainstTlsa,
  matchDane,
  certAssociationData,
} from "rolodex-ca-client";

// Rolodex publishes DANE-TA ("2 1 1") records for the per-zone intermediate
// at _<port>._<proto>.<name> on issuance.
const records = await fetchTlsaRecords("host.example.com", {
  port: 443,          // TLSA service port (owner name)
  protocol: "tcp",
  dnsServer: "127.0.0.1",
  dnsPort: 53,
  // transport: "tcp" to force TCP; UDP responses with TC retry over TCP.
});
// [{ usage: 2, selector: 1, matchingType: 1, data: "<sha256 hex>" }]

verifyCertAgainstTlsa(intermediatePem, records[0]); // true
matchDane(records, leafPlusIntermediatePem);        // { record, certPem, certIndex }
certAssociationData(certPem, 1, 1);                 // sha256(SPKI) hex
```

## Local UI

```sh
npm run ui -- --portal https://127.0.0.1:8500 --insecure \
              --bind 127.0.0.1:8600 --dns 127.0.0.1:53
```

Then open `http://127.0.0.1:8600`: root CA download, EAB enrollment,
issued-certificate listing, and live TLSA lookups with optional certificate
verification.

## Tests

From the repo root:

- `make js-test` — lint, integration tests (spawns a real `rolodex-dns`
  server), then unit tests.
- `make js-integration-test` — just the live-server tests; the DANE test
  cross-checks the Rust-published TLSA record against hashes recomputed in JS.

Unit-test fixtures in `test/fixtures/` were generated with openssl (Ed25519,
matching the issuer's key type); `expected.json` holds openssl-computed SPKI
and certificate digests used as an oracle independent of `node:crypto`.
