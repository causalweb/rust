#![allow(dead_code)]
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use causalweb::{
    CLAIM, PROFILE,
    evidence::{Issuer, IssuerTrust, Limits, SigningKey, Verifier, VerifyingKey},
    prefix::{Frontier, Mapping, Snapshot},
};
use p256::ecdsa::{Signature, signature::Signer};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

pub const ISSUER: &str = "https://issuer.example";
pub const DOMAIN: &str = "https://issuer.example/domains/a";
pub const OTHER_DOMAIN: &str = "https://issuer.example/domains/b";
pub const SUBJECT: &str = "opaque-tenant";
pub const AUDIENCE: &str = "https://verifier.example/causal";
pub const TARGET: &str = "/orders/123";

pub fn limits() -> Limits {
    Limits {
        max_requirements: 16,
        max_header_bytes: 16384,
        max_token_bytes: 8192,
        max_decoded_bytes: 8192,
        max_json_depth: 32,
    }
}
pub fn claims(position: &str) -> Value {
    json!({"iss":ISSUER,"sub":SUBJECT,"aud":AUDIENCE,"iat":1,"exp":1000,"jti":"urn:test:ephemeral-evidence",
        CLAIM:{"v":1,"profile":PROFILE,"domain":DOMAIN,"position":position,"commit":"stable"}})
}
pub fn verifier(key: VerifyingKey) -> Verifier {
    verifier_with(key, limits(), 0)
}
pub fn verifier_with(key: VerifyingKey, limits: Limits, skew: u64) -> Verifier {
    Verifier::new(
        AUDIENCE.into(),
        vec![IssuerTrust {
            issuer: ISSUER.into(),
            keys: BTreeMap::from([("test-key".into(), key)]),
            domains: BTreeSet::from([DOMAIN.into(), OTHER_DOMAIN.into()]),
            max_lifetime_seconds: 86400,
            clock_skew_seconds: skew,
        }],
        limits,
    )
    .unwrap()
}
pub fn header() -> Value {
    json!({"alg":"ES256","kid":"test-key","typ":"cw-evidence+jwt"})
}
pub fn sign_bytes(key: &SigningKey, header: &[u8], payload: &[u8]) -> String {
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header),
        URL_SAFE_NO_PAD.encode(payload)
    );
    let sig: Signature = key.sign(input.as_bytes());
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()))
}
pub fn sign(key: &SigningKey, claims: &Value) -> String {
    sign_bytes(
        key,
        &serde_json::to_vec(&header()).unwrap(),
        &serde_json::to_vec(claims).unwrap(),
    )
}
pub fn issuer(key: SigningKey) -> Issuer {
    Issuer::new(
        ISSUER.into(),
        "test-key".into(),
        key,
        BTreeSet::from([DOMAIN.into()]),
        86400,
        limits(),
    )
    .unwrap()
}
pub fn snapshot<T>(representation: T, frontiers: Vec<Frontier>) -> Snapshot<T> {
    Snapshot::new(
        TARGET.into(),
        representation,
        "orders-projection/v1".into(),
        "orders-view/v1".into(),
        BTreeMap::from([(
            (ISSUER.into(), DOMAIN.into()),
            Mapping::Relevant {
                component_frontiers: frontiers,
                first_terminal_failure: None,
                progress_possible: true,
            },
        )]),
    )
    .unwrap()
}
