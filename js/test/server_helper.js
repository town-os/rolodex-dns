// Shared harness for JS integration tests: spawns a real rolodex-dns server
// in an isolated temp dir with random ports. Gated on ROLODEX_DNS_BINARY.

import { spawn, execFile } from "node:child_process";
import { promisify } from "node:util";
import { mkdtempSync, rmSync, writeFileSync, existsSync } from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";

const execFileP = promisify(execFile);

export const BINARY = process.env.ROLODEX_DNS_BINARY ?? "";
export const CLI_BINARY =
  process.env.ROLODEX_DNS_CLI_BINARY ||
  (BINARY ? path.join(path.dirname(BINARY), "rolodex-dns-cli") : "");

export const skip = BINARY
  ? false
  : "ROLODEX_DNS_BINARY not set; run via `make js-integration-test`";

export function allocatePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.listen(0, "127.0.0.1", () => {
      const { port } = srv.address();
      srv.close(() => resolve(port));
    });
    srv.on("error", reject);
  });
}

export function waitForPort(port, timeoutMs = 10000) {
  const deadline = Date.now() + timeoutMs;
  return new Promise((resolve, reject) => {
    const attempt = () => {
      const sock = net.connect({ host: "127.0.0.1", port, timeout: 250 });
      sock.on("connect", () => {
        sock.destroy();
        resolve();
      });
      const retry = () => {
        sock.destroy();
        if (Date.now() > deadline) {
          reject(new Error(`port ${port} did not open within ${timeoutMs}ms`));
        } else {
          setTimeout(attempt, 100);
        }
      };
      sock.on("error", retry);
      sock.on("timeout", retry);
    };
    attempt();
  });
}

export async function waitForFile(file, timeoutMs = 10000) {
  const deadline = Date.now() + timeoutMs;
  while (!existsSync(file)) {
    if (Date.now() > deadline) {
      throw new Error(`${file} did not appear within ${timeoutMs}ms`);
    }
    await new Promise((r) => setTimeout(r, 100));
  }
}

/**
 * Starts a rolodex-dns server with the ACME issuer enabled (and DoH when
 * `doh: true`). Registers cleanup on the test context `t`. Returns
 * `{ dir, socketPath, dnsPort, acmePort, portalPort, dohPort }`.
 */
export async function startServer(t, opts = {}) {
  const dir = mkdtempSync(path.join(os.tmpdir(), "rolodex-js-"));
  const socketPath = path.join(dir, "rolodex.sock");
  const dnsPort = await allocatePort();
  const acmePort = await allocatePort();
  const portalPort = await allocatePort();
  const dohPort = opts.doh ? await allocatePort() : null;

  let config = `database_path: "${path.join(dir, "rolodex-dns.db")}"
forwarders: []
resolution:
  mode: forward

dns:
  bind:
    - udp: "127.0.0.1:${dnsPort}"
    - tcp: "127.0.0.1:${dnsPort}"

grpc:
  tcp_bind: ""
  unix_socket: "${socketPath}"
  shared_secret: ""

rbl:
  enabled: false
  providers: []

acme:
  bind: "127.0.0.1:${acmePort}"
  portal_bind: "127.0.0.1:${portalPort}"
  directory_url: "https://127.0.0.1:${acmePort}/acme"
`;
  if (dohPort) {
    config += `
doh:
  bind: "127.0.0.1:${dohPort}"
`;
  }
  const configPath = path.join(dir, "rolodex-dns.yml");
  writeFileSync(configPath, config);

  const proc = spawn(BINARY, ["-c", configPath], {
    stdio: ["ignore", "inherit", "inherit"],
  });

  t.after(() => {
    proc.kill("SIGKILL");
    rmSync(dir, { recursive: true, force: true });
  });

  await waitForPort(portalPort);
  await waitForPort(dnsPort); // DNS TCP listener
  if (dohPort) {
    await waitForPort(dohPort);
  }
  await waitForFile(socketPath);

  return { dir, socketPath, dnsPort, acmePort, portalPort, dohPort };
}

/** Runs rolodex-dns-cli against the server's Unix socket. */
export function cli(socketPath, args) {
  return execFileP(CLI_BINARY, ["--unix-socket", socketPath, ...args]);
}
