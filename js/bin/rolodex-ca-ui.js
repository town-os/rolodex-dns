#!/usr/bin/env node
// Local enrollment UI for the Rolodex ACME issuer.
//
// Usage:
//   rolodex-ca-ui --portal https://127.0.0.1:8500 [--bind 127.0.0.1:8600]
//                 [--dns 127.0.0.1:53] [--ca root.pem] [--insecure]
//
// Serves the enrollment + DANE console on --bind, proxying portal API calls
// (over the portal's self-signed TLS) and performing TLSA lookups against the
// DNS server given by --dns.

import { readFileSync } from "node:fs";
import { createUiServer } from "../src/ui_server.js";

function usage(code) {
  console.error(
    "usage: rolodex-ca-ui --portal <url> [--bind host:port] [--dns host:port] [--ca pem-file] [--insecure]",
  );
  process.exit(code);
}

function parseArgs(argv) {
  const opts = {
    portal: "https://127.0.0.1:8500",
    bind: "127.0.0.1:8600",
    dns: "127.0.0.1:53",
    ca: null,
    insecure: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    const next = () => {
      i += 1;
      if (i >= argv.length) usage(1);
      return argv[i];
    };
    switch (arg) {
      case "--portal":
        opts.portal = next();
        break;
      case "--bind":
        opts.bind = next();
        break;
      case "--dns":
        opts.dns = next();
        break;
      case "--ca":
        opts.ca = next();
        break;
      case "--insecure":
        opts.insecure = true;
        break;
      case "--help":
      case "-h":
        usage(0);
        break;
      default:
        console.error(`unknown argument: ${arg}`);
        usage(1);
    }
  }
  return opts;
}

function splitHostPort(value, defaultPort) {
  const idx = value.lastIndexOf(":");
  if (idx === -1) {
    return { host: value, port: defaultPort };
  }
  return { host: value.slice(0, idx), port: Number(value.slice(idx + 1)) };
}

const opts = parseArgs(process.argv.slice(2));
const bind = splitHostPort(opts.bind, 8600);
const dns = splitHostPort(opts.dns, 53);

const server = createUiServer({
  portalUrl: opts.portal,
  ca: opts.ca ? readFileSync(opts.ca) : undefined,
  insecure: opts.insecure,
  dnsServer: dns.host,
  dnsPort: dns.port,
});

server.listen(bind.port, bind.host, () => {
  console.log(`rolodex-ca-ui listening on http://${bind.host}:${bind.port}`);
  console.log(`  portal: ${opts.portal}${opts.insecure ? " (TLS verification disabled)" : ""}`);
  console.log(`  dane lookups via DNS ${dns.host}:${dns.port}`);
});
