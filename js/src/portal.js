// Client for the Rolodex DNS trusted-network enrollment portal JSON API.
//
// The portal (served on `acme.portal_bind`) is the self-service surface of the
// ACME issuer: it mints EAB credentials scoped to a zone, exposes the root CA
// for download, and lists enrollable zones and issued certificates. This is
// the same API used by the built-in web portal and the browser extension.
//
// The portal listener uses TLS with an auto-generated self-signed certificate
// by default, so callers either pass the server certificate via `ca` or set
// `insecure: true` to skip verification (acceptable only on the trusted
// network the portal is restricted to).

import https from "node:https";

/** Error raised for non-2xx portal responses, carrying the HTTP status. */
export class PortalError extends Error {
  constructor(message, status = null) {
    super(message);
    this.name = "PortalError";
    this.status = status;
  }
}

export class PortalClient {
  /**
   * @param {string} baseUrl Portal base URL, e.g. "https://127.0.0.1:8500".
   *   A bare "host:port" is treated as https.
   * @param {object} [opts]
   * @param {string|Buffer} [opts.ca] PEM CA bundle to trust for the portal's
   *   TLS certificate.
   * @param {boolean} [opts.insecure] Skip TLS certificate verification.
   * @param {number} [opts.timeoutMs] Per-request timeout (default 10000).
   */
  constructor(baseUrl, opts = {}) {
    const normalized = /^[a-z]+:\/\//i.test(baseUrl)
      ? baseUrl
      : `https://${baseUrl}`;
    this.base = new URL(normalized);
    this.ca = opts.ca ?? null;
    this.insecure = opts.insecure === true;
    this.timeoutMs = opts.timeoutMs ?? 10000;
  }

  /** Downloads the Rolodex root CA as PEM text (`GET /api/ca`). */
  async getCaPem() {
    const { body } = await this.#request("GET", "/api/ca");
    return body.toString("utf8");
  }

  /** Lists zones that can be enrolled (`GET /api/zones`). */
  async listZones() {
    const { body } = await this.#request("GET", "/api/zones");
    return JSON.parse(body.toString("utf8")).zones ?? [];
  }

  /**
   * Lists issued certificates (`GET /api/certs`), optionally filtered by
   * zone. Returns `[{ domain, issued_at, expires_at }]`.
   */
  async listCertificates(zone = null) {
    const path = zone
      ? `/api/certs?zone=${encodeURIComponent(zone)}`
      : "/api/certs";
    const { body } = await this.#request("GET", path);
    return JSON.parse(body.toString("utf8")).certificates ?? [];
  }

  /**
   * Mints an EAB credential for `zone` (`POST /api/account`), creating the
   * per-zone intermediate CA if needed. Returns
   * `{ directory_url, zone, eab_kid, eab_hmac_key, snippets }`.
   */
  async createAccount(zone) {
    const { body } = await this.#request("POST", "/api/account", { zone });
    return JSON.parse(body.toString("utf8"));
  }

  #request(method, path, jsonBody = null) {
    const url = new URL(path, this.base);
    const payload = jsonBody === null ? null : JSON.stringify(jsonBody);

    const options = {
      method,
      headers: { accept: "application/json, application/x-pem-file" },
      timeout: this.timeoutMs,
    };
    if (payload !== null) {
      options.headers["content-type"] = "application/json";
      options.headers["content-length"] = Buffer.byteLength(payload);
    }
    if (this.ca) {
      options.ca = this.ca;
    }
    if (this.insecure) {
      options.rejectUnauthorized = false;
    }

    return new Promise((resolve, reject) => {
      const req = https.request(url, options, (res) => {
        const chunks = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => {
          const body = Buffer.concat(chunks);
          if (res.statusCode < 200 || res.statusCode >= 300) {
            reject(
              new PortalError(
                `${method} ${path} failed: ${res.statusCode} ${body.toString("utf8")}`,
                res.statusCode,
              ),
            );
            return;
          }
          resolve({ status: res.statusCode, body });
        });
      });
      req.on("timeout", () => {
        req.destroy(new PortalError(`${method} ${path} timed out`));
      });
      req.on("error", reject);
      if (payload !== null) {
        req.write(payload);
      }
      req.end();
    });
  }
}
