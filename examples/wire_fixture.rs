//! Synthetic conformance exchange, not a durable source/projection demonstration.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use causalweb::{
    CLAIM, PROFILE,
    evidence::{Issuer, IssuerTrust, Limits, SigningKey, Verifier},
    http as cw_http,
    prefix::{Frontier, Mapping, Snapshot},
};
use http::{Request, Response};
use p256::elliptic_curve::Generate;
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let limits = Limits {
        max_requirements: 16,
        max_header_bytes: 16384,
        max_token_bytes: 8192,
        max_decoded_bytes: 8192,
        max_json_depth: 32,
    };
    let key = SigningKey::generate();
    let point = key.verifying_key().to_sec1_point(false);
    let bytes = point.as_bytes();
    let public_jwk = json!({"kty":"EC", "crv":"P-256", "kid":"test-key", "alg":"ES256", "use":"sig",
        "x":URL_SAFE_NO_PAD.encode(&bytes[1..33]), "y":URL_SAFE_NO_PAD.encode(&bytes[33..65])});
    let domain = "https://issuer.example/domains/test";
    let verifier = Verifier::new(
        "https://verifier.example/causal".into(),
        vec![IssuerTrust {
            issuer: "https://issuer.example".into(),
            keys: BTreeMap::from([("test-key".into(), *key.verifying_key())]),
            domains: BTreeSet::from([domain.into()]),
            max_lifetime_seconds: 1000,
            clock_skew_seconds: 0,
        }],
        limits,
    )?;
    let issuer = Issuer::new(
        "https://issuer.example".into(),
        "test-key".into(),
        key,
        BTreeSet::from([domain.into()]),
        1000,
        limits,
    )?;
    let claims = json!({"iss":"https://issuer.example", "sub":"opaque-test-subject", "aud":"https://verifier.example/causal",
        "iat":1, "exp":1000, "jti":"urn:test:synthetic-wire-fixture", CLAIM:{"v":1,"profile":PROFILE,"domain":domain,"position":"5","commit":"stable"}});
    let compact = issuer.issue_committed(&claims, 100)?;
    let mut request = Request::new(());
    *request.headers_mut() = cw_http::request_headers(std::slice::from_ref(&compact), limits)?;
    let read = |frontier| {
        Snapshot::new(
            "/test".into(),
            Response::new(b"indexed".to_vec()),
            "test/v1".into(),
            "test-schema/v1".into(),
            BTreeMap::from([(
                ("https://issuer.example".into(), domain.into()),
                Mapping::Relevant {
                    component_frontiers: vec![Frontier::At(frontier)],
                    first_terminal_failure: None,
                    progress_possible: true,
                },
            )]),
        )
    };
    let stale = cw_http::observe(
        &request,
        "/test",
        true,
        &verifier,
        "opaque-test-subject",
        || true,
        || 100,
        || read(4).map_err(|_| ()),
    );
    let fresh = cw_http::observe(
        &request,
        "/test",
        true,
        &verifier,
        "opaque-test-subject",
        || true,
        || 100,
        || read(5).map_err(|_| ()),
    );
    cw_http::accept_confirmation(&fresh, true)?;
    println!(
        "{}",
        json!({"synthetic_test_fixture":true,"compact":compact,"public_jwk":public_jwk,
        "stale_status":stale.status().as_u16(),"fresh_status":fresh.status().as_u16(),"confirmed":true})
    );
    Ok(())
}
