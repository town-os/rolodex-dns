// JavaScript client for the Rolodex DNS ACME issuer.
//
// - `PortalClient`: enrollment portal JSON API (EAB minting, root CA download,
//   zone and certificate listing).
// - DANE helpers: TLSA retrieval over the DNS wire protocol and verification
//   of records against PEM certificates.
// - `createUiServer`: a local enrollment UI that proxies the portal and adds
//   browser-accessible DANE lookups.

export { PortalClient, PortalError } from "./portal.js";
export {
  TLSA_TYPE,
  DnsError,
  tlsaName,
  tlsaValue,
  encodeName,
  decodeName,
  encodeQuery,
  encodeResponse,
  decodeMessage,
  parseTlsaRdata,
  encodeTlsaRdata,
  queryDns,
  fetchTlsaRecords,
  splitPemCertificates,
  certAssociationData,
  verifyCertAgainstTlsa,
  matchDane,
} from "./dane.js";
export { createUiServer } from "./ui_server.js";
