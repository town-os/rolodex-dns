//! JOSE / JWS verification for the ACME server.
//!
//! Implements the subset of RFC 7515 (JWS), RFC 7517 (JWK), and RFC 7638 (JWK
//! thumbprint) that an ACME server (RFC 8555) needs:
//!
//! - Verify the flattened JWS each ACME request is wrapped in, against either an
//!   embedded `jwk` (newAccount) or a resolved account key.
//! - Compute the RFC 7638 JWK thumbprint (account identity + dns-01 key auth).
//! - Verify an External Account Binding (EAB) inner JWS (HMAC-SHA256).
//!
//! Supported signature algorithms: `EdDSA` (Ed25519), `ES256` (ECDSA P-256), and
//! `RS256` (RSA PKCS#1 v1.5). All signatures are verified with `ring`.

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use ring::{hmac, signature};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

/// A parsed flattened JWS (RFC 7515 §7.2.2), as ACME clients send.
#[derive(Debug, Deserialize)]
pub struct FlatJws {
    pub protected: String,
    pub payload: String,
    pub signature: String,
}

/// The decoded JWS protected header fields relevant to ACME.
#[derive(Debug, Default)]
pub struct ProtectedHeader {
    pub alg: String,
    pub nonce: Option<String>,
    pub url: Option<String>,
    pub kid: Option<String>,
    pub jwk: Option<Value>,
}

impl FlatJws {
    /// Parses a flattened JWS from a request body.
    pub fn parse(body: &[u8]) -> Result<Self> {
        serde_json::from_slice(body).context("invalid JWS body")
    }

    /// Decodes the protected header.
    pub fn protected_header(&self) -> Result<ProtectedHeader> {
        let raw = B64
            .decode(self.protected.as_bytes())
            .context("protected header is not valid base64url")?;
        let v: Value = serde_json::from_slice(&raw).context("protected header is not JSON")?;
        Ok(ProtectedHeader {
            alg: v
                .get("alg")
                .and_then(Value::as_str)
                .context("protected header missing alg")?
                .to_string(),
            nonce: v.get("nonce").and_then(Value::as_str).map(str::to_string),
            url: v.get("url").and_then(Value::as_str).map(str::to_string),
            kid: v.get("kid").and_then(Value::as_str).map(str::to_string),
            jwk: v.get("jwk").cloned(),
        })
    }

    /// Decodes the payload as JSON. An empty payload (POST-as-GET) yields `Null`.
    pub fn payload_json(&self) -> Result<Value> {
        if self.payload.is_empty() {
            return Ok(Value::Null);
        }
        let raw = B64
            .decode(self.payload.as_bytes())
            .context("payload is not valid base64url")?;
        if raw.is_empty() {
            return Ok(Value::Null);
        }
        serde_json::from_slice(&raw).context("payload is not JSON")
    }

    /// The JWS signing input: `base64url(protected) || '.' || base64url(payload)`.
    fn signing_input(&self) -> Vec<u8> {
        format!("{}.{}", self.protected, self.payload).into_bytes()
    }

    /// Verifies the outer JWS signature against the given public key JWK.
    pub fn verify(&self, alg: &str, jwk: &Value) -> Result<()> {
        let sig = B64
            .decode(self.signature.as_bytes())
            .context("signature is not valid base64url")?;
        verify_with_jwk(alg, jwk, &self.signing_input(), &sig)
    }
}

/// Verifies a signature over `message` using the public key described by `jwk`.
fn verify_with_jwk(alg: &str, jwk: &Value, message: &[u8], sig: &[u8]) -> Result<()> {
    let kty = jwk
        .get("kty")
        .and_then(Value::as_str)
        .context("jwk missing kty")?;
    match (alg, kty) {
        ("EdDSA", "OKP") => {
            let x = jwk_field_bytes(jwk, "x")?;
            signature::UnparsedPublicKey::new(&signature::ED25519, x)
                .verify(message, sig)
                .map_err(|_| anyhow!("Ed25519 signature verification failed"))
        }
        ("ES256", "EC") => {
            let mut point = Vec::with_capacity(65);
            point.push(0x04);
            point.extend_from_slice(&jwk_field_bytes(jwk, "x")?);
            point.extend_from_slice(&jwk_field_bytes(jwk, "y")?);
            signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, point)
                .verify(message, sig)
                .map_err(|_| anyhow!("ES256 signature verification failed"))
        }
        ("RS256", "RSA") => {
            let n = jwk_field_bytes(jwk, "n")?;
            let e = jwk_field_bytes(jwk, "e")?;
            let pk = signature::RsaPublicKeyComponents { n: &n, e: &e };
            pk.verify(&signature::RSA_PKCS1_2048_8192_SHA256, message, sig)
                .map_err(|_| anyhow!("RS256 signature verification failed"))
        }
        _ => bail!("unsupported JWS alg/kty combination: {}/{}", alg, kty),
    }
}

/// Decodes a base64url JWK member into bytes.
fn jwk_field_bytes(jwk: &Value, field: &str) -> Result<Vec<u8>> {
    let s = jwk
        .get(field)
        .and_then(Value::as_str)
        .with_context(|| format!("jwk missing {}", field))?;
    B64.decode(s.as_bytes())
        .with_context(|| format!("jwk {} is not valid base64url", field))
}

/// Computes the RFC 7638 JWK thumbprint (base64url SHA-256 of the canonical JWK).
pub fn jwk_thumbprint(jwk: &Value) -> Result<String> {
    let kty = jwk
        .get("kty")
        .and_then(Value::as_str)
        .context("jwk missing kty")?;
    // Canonical form: required members only, lexicographic order, no whitespace.
    let canonical = match kty {
        "OKP" => format!(
            r#"{{"crv":"{}","kty":"OKP","x":"{}"}}"#,
            jwk_str(jwk, "crv")?,
            jwk_str(jwk, "x")?
        ),
        "EC" => format!(
            r#"{{"crv":"{}","kty":"EC","x":"{}","y":"{}"}}"#,
            jwk_str(jwk, "crv")?,
            jwk_str(jwk, "x")?,
            jwk_str(jwk, "y")?
        ),
        "RSA" => format!(
            r#"{{"e":"{}","kty":"RSA","n":"{}"}}"#,
            jwk_str(jwk, "e")?,
            jwk_str(jwk, "n")?
        ),
        other => bail!("unsupported jwk kty for thumbprint: {}", other),
    };
    Ok(B64.encode(Sha256::digest(canonical.as_bytes())))
}

fn jwk_str<'a>(jwk: &'a Value, field: &str) -> Result<&'a str> {
    jwk.get(field)
        .and_then(Value::as_str)
        .with_context(|| format!("jwk missing {}", field))
}

/// The ACME key authorization for a challenge: `token "." base64url(thumbprint)`.
pub fn key_authorization(token: &str, account_thumbprint: &str) -> String {
    format!("{}.{}", token, account_thumbprint)
}

/// The expected dns-01 TXT record value: `base64url(SHA-256(keyAuthorization))`.
pub fn dns01_txt_value(key_authorization: &str) -> String {
    B64.encode(Sha256::digest(key_authorization.as_bytes()))
}

/// Verifies an External Account Binding inner JWS (RFC 8555 §7.3.4).
///
/// The EAB is a flattened JWS signed with HMAC-SHA256 using the shared `hmac_key`
/// identified by the `kid` in its protected header. Its payload MUST be the
/// account public key JWK. Returns the EAB `kid` on success.
pub fn verify_eab(eab: &Value, account_jwk: &Value, hmac_key: &[u8]) -> Result<()> {
    let protected_b64 = eab
        .get("protected")
        .and_then(Value::as_str)
        .context("EAB missing protected")?;
    let payload_b64 = eab
        .get("payload")
        .and_then(Value::as_str)
        .context("EAB missing payload")?;
    let sig_b64 = eab
        .get("signature")
        .and_then(Value::as_str)
        .context("EAB missing signature")?;

    // Verify the HMAC over the signing input.
    let signing_input = format!("{}.{}", protected_b64, payload_b64);
    let sig = B64
        .decode(sig_b64.as_bytes())
        .context("EAB signature is not valid base64url")?;
    let key = hmac::Key::new(hmac::HMAC_SHA256, hmac_key);
    hmac::verify(&key, signing_input.as_bytes(), &sig)
        .map_err(|_| anyhow!("EAB HMAC verification failed"))?;

    // The EAB protected header must declare HS256.
    let prot_raw = B64
        .decode(protected_b64.as_bytes())
        .context("EAB protected is not valid base64url")?;
    let prot: Value = serde_json::from_slice(&prot_raw).context("EAB protected is not JSON")?;
    if prot.get("alg").and_then(Value::as_str) != Some("HS256") {
        bail!("EAB alg must be HS256");
    }

    // The EAB payload must equal the account public key JWK.
    let payload_raw = B64
        .decode(payload_b64.as_bytes())
        .context("EAB payload is not valid base64url")?;
    let payload: Value = serde_json::from_slice(&payload_raw).context("EAB payload is not JSON")?;
    if payload != *account_jwk {
        bail!("EAB payload does not match the account key");
    }
    Ok(())
}

/// Extracts the `kid` from an EAB's protected header.
pub fn eab_kid(eab: &Value) -> Result<String> {
    let protected_b64 = eab
        .get("protected")
        .and_then(Value::as_str)
        .context("EAB missing protected")?;
    let raw = B64
        .decode(protected_b64.as_bytes())
        .context("EAB protected is not valid base64url")?;
    let prot: Value = serde_json::from_slice(&raw).context("EAB protected is not JSON")?;
    prot.get("kid")
        .and_then(Value::as_str)
        .map(str::to_string)
        .context("EAB protected missing kid")
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair};

    /// Builds an Ed25519 account JWK + signing key for tests.
    fn ed25519_jwk() -> (Ed25519KeyPair, Value) {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).expect("gen");
        let kp = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("kp");
        let x = B64.encode(kp.public_key().as_ref());
        let jwk = serde_json::json!({"kty":"OKP","crv":"Ed25519","x":x});
        (kp, jwk)
    }

    fn flat_sign(kp: &Ed25519KeyPair, protected: &Value, payload: &Value) -> FlatJws {
        let protected_b64 = B64.encode(serde_json::to_vec(protected).unwrap());
        let payload_b64 = if payload.is_null() {
            String::new()
        } else {
            B64.encode(serde_json::to_vec(payload).unwrap())
        };
        let signing_input = format!("{}.{}", protected_b64, payload_b64);
        let sig = kp.sign(signing_input.as_bytes());
        FlatJws {
            protected: protected_b64,
            payload: payload_b64,
            signature: B64.encode(sig.as_ref()),
        }
    }

    #[test]
    fn ed25519_jws_round_trip() {
        let (kp, jwk) = ed25519_jwk();
        let protected = serde_json::json!({"alg":"EdDSA","nonce":"abc","url":"https://x/acme/new-order","jwk":jwk});
        let payload = serde_json::json!({"identifiers":[{"type":"dns","value":"a.example.com"}]});
        let jws = flat_sign(&kp, &protected, &payload);

        let hdr = jws.protected_header().expect("hdr");
        assert_eq!(hdr.alg, "EdDSA");
        assert_eq!(hdr.nonce.as_deref(), Some("abc"));
        jws.verify("EdDSA", &jwk).expect("valid signature");
    }

    #[test]
    fn tampered_payload_is_rejected() {
        let (kp, jwk) = ed25519_jwk();
        let protected = serde_json::json!({"alg":"EdDSA","jwk":jwk});
        let payload = serde_json::json!({"a":1});
        let mut jws = flat_sign(&kp, &protected, &payload);
        // Tamper the payload after signing.
        jws.payload = B64.encode(serde_json::to_vec(&serde_json::json!({"a":2})).unwrap());
        assert!(jws.verify("EdDSA", &jwk).is_err());
    }

    #[test]
    fn thumbprint_is_stable_and_base64url() {
        let (_, jwk) = ed25519_jwk();
        let t1 = jwk_thumbprint(&jwk).expect("t1");
        let t2 = jwk_thumbprint(&jwk).expect("t2");
        assert_eq!(t1, t2);
        // base64url SHA-256 (32 bytes) with no padding is 43 chars.
        assert_eq!(t1.len(), 43);
        assert!(!t1.contains('='));
    }

    #[test]
    fn dns01_value_matches_spec_shape() {
        let ka = key_authorization("tok123", "thumb456");
        assert_eq!(ka, "tok123.thumb456");
        let txt = dns01_txt_value(&ka);
        assert_eq!(txt.len(), 43); // base64url SHA-256, no padding
    }

    #[test]
    fn eab_hmac_round_trip() {
        let (_, account_jwk) = ed25519_jwk();
        let hmac_key = b"super-secret-eab-key-bytes-000000";
        let eab_protected =
            serde_json::json!({"alg":"HS256","kid":"kid-1","url":"https://x/acme/new-account"});
        let prot_b64 = B64.encode(serde_json::to_vec(&eab_protected).unwrap());
        let payload_b64 = B64.encode(serde_json::to_vec(&account_jwk).unwrap());
        let signing_input = format!("{}.{}", prot_b64, payload_b64);
        let key = hmac::Key::new(hmac::HMAC_SHA256, hmac_key);
        let tag = hmac::sign(&key, signing_input.as_bytes());
        let eab = serde_json::json!({
            "protected": prot_b64,
            "payload": payload_b64,
            "signature": B64.encode(tag.as_ref()),
        });

        assert_eq!(eab_kid(&eab).unwrap(), "kid-1");
        verify_eab(&eab, &account_jwk, hmac_key).expect("valid EAB");
        // Wrong key fails.
        assert!(verify_eab(&eab, &account_jwk, b"wrong-key").is_err());
    }
}
