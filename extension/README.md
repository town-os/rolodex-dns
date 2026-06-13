# Rolodex DNS Enrollment — Browser Extension

A Manifest V3 browser extension that provides the same self-service certificate
enrollment as the built-in web portal, against a Rolodex DNS ACME issuer. It
calls the trusted-network `/api/*` surface served by `acme.portal_bind`, and can
additionally retrieve the CA chain **from DNS itself** over DoH — for any client
that can resolve the zone, no portal access required.

## What it does

1. You enter your Rolodex **portal URL** (e.g. `https://dns.example.com:8500`).
2. It lists the **zones** that have a per-zone CA.
3. **Enroll** mints an EAB account scoped to the chosen zone and shows ready-to-paste
   `lego` / `certbot` / `Caddy` config (with the EAB key id + HMAC key).
4. **Download root CA** opens the root CA PEM so you can trust it.

It shares the exact API the web portal uses, so anything you can do here you can
also do in a plain browser at the portal URL.

## CA via DNS (portal-independent)

Rolodex publishes its CA chain into DNS whenever a per-zone CA is created:

- **CERT records** (RFC 4398) at `_ca.<zone>.` — root + intermediate, each as
  `1 0 0 <base64 DER>` (PKIX). `dig CERT _ca.<zone>` works too.
- **TXT records** at `_rolodex-ca.<zone>.` — the same base64 DER chunked and
  framed as `rolodex-ca:v1:<root|intermediate>:<i>/<n>:<chunk>`, a fallback
  for stacks that cannot query CERT. The unique `rolodex-ca:` prefix keeps the
  chunks distinguishable from unrelated TXT data.

The **CA via DNS** section of the popup takes a **DoH URL** (the Rolodex DoH
listener, e.g. `https://dns.example.com/dns-query`) and a **zone**, queries the
CERT records first and falls back to TXT, identifies the root (self-signed) vs
the intermediate, and offers root / intermediate / chain PEM downloads.
Optionally it verifies the retrieved intermediate against the DANE-TA TLSA
record (`2 1 1`, SHA-256 of the intermediate SPKI) published for a hostname.

The DNS logic lives in `ca_dns.js`, a browser ES module (DNS wire codec, DoH
POST, minimal X.509 DER walking, WebCrypto hashing) that is also imported and
tested by the Node test suite in `js/test/`.

## Install (unpacked)

Chromium (Chrome/Edge/Brave):

1. Visit `chrome://extensions`.
2. Enable **Developer mode**.
3. **Load unpacked** → select this `extension/` directory.
4. Click the extension, enter your portal URL, and **Load**.

Firefox:

1. Visit `about:debugging#/runtime/this-firefox`.
2. **Load Temporary Add-on…** → select `manifest.json`.

The extension requests host permission for the portal origin only when you first
talk to it (MV3 `optional_host_permissions`).

## Security

The portal is **trusted-network only** — it performs no per-user authentication
and anyone who can reach `portal_bind` can mint enrollment credentials. Keep
`portal_bind` on an internal interface. Store packaging/signing is out of scope
for this initial version.
