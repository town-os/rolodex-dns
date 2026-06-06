# Rolodex DNS Enrollment — Browser Extension

A Manifest V3 browser extension that provides the same self-service certificate
enrollment as the built-in web portal, against a Rolodex DNS ACME issuer. It
calls the trusted-network `/api/*` surface served by `acme.portal_bind`.

## What it does

1. You enter your Rolodex **portal URL** (e.g. `https://dns.example.com:8500`).
2. It lists the **zones** that have a per-zone CA.
3. **Enroll** mints an EAB account scoped to the chosen zone and shows ready-to-paste
   `lego` / `certbot` / `Caddy` config (with the EAB key id + HMAC key).
4. **Download root CA** opens the root CA PEM so you can trust it.

It shares the exact API the web portal uses, so anything you can do here you can
also do in a plain browser at the portal URL.

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
