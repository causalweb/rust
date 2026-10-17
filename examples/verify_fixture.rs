//! Trusted test-harness input only. This is not a service that accepts remote trust configuration.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use causalweb::{
    evidence::{IssuerTrust, Limits, Verifier, VerifyingKey},
    http as cw_http,
    prefix::{Frontier, Mapping, Snapshot},
};
use http::{Request, Response};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{self, Read},
};

#[derive(Deserialize)]
struct Input {
    issuer: String,
    subject: String,
    audience: String,
    domain: String,
    kid: String,
    public_jwk: Value,
    compact: String,
    now: u64,
    frontier: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut bytes = Vec::new();
    io::stdin().take(65537).read_to_end(&mut bytes)?;
    if bytes.len() > 65536 {
        return Err("test input exceeds limit".into());
    }
    let input: Input = serde_json::from_slice(&bytes)?;
    if input.public_jwk["kty"] != "EC" || input.public_jwk["crv"] != "P-256" {
        return Err("invalid test key".into());
    }
    let mut point = vec![4];
    point.extend(URL_SAFE_NO_PAD.decode(input.public_jwk["x"].as_str().ok_or("missing x")?)?);
    point.extend(URL_SAFE_NO_PAD.decode(input.public_jwk["y"].as_str().ok_or("missing y")?)?);
    let limits = Limits {
        max_requirements: 16,
        max_header_bytes: 16384,
        max_token_bytes: 8192,
        max_decoded_bytes: 8192,
        max_json_depth: 32,
    };
    let verifier = Verifier::new(
        input.audience,
        vec![IssuerTrust {
            issuer: input.issuer.clone(),
            keys: BTreeMap::from([(input.kid, VerifyingKey::from_sec1_bytes(&point)?)]),
            domains: BTreeSet::from([input.domain.clone()]),
            max_lifetime_seconds: 86400,
            clock_skew_seconds: 0,
        }],
        limits,
    )?;
    let mut request = Request::new(());
    *request.headers_mut() = cw_http::request_headers(&[input.compact], limits)?;
    let frontier = causalweb::prefix::position(&input.frontier)?;
    let response = cw_http::observe(
        &request,
        "/test",
        true,
        &verifier,
        &input.subject,
        || true,
        || input.now,
        || {
            Snapshot::new(
                "/test".into(),
                Response::new(b"indexed".to_vec()),
                "test/v1".into(),
                "test-schema/v1".into(),
                BTreeMap::from([(
                    (input.issuer, input.domain),
                    Mapping::Relevant {
                        component_frontiers: vec![Frontier::At(frontier)],
                        first_terminal_failure: None,
                        progress_possible: true,
                    },
                )]),
            )
            .map_err(|_| ())
        },
    );
    let result = response
        .headers()
        .get(cw_http::RESULT)
        .and_then(|h| h.to_str().ok());
    println!(
        "{}",
        json!({"status":response.status().as_u16(),"causal_result":result,
        "confirmed":cw_http::accept_confirmation(&response, true).is_ok()})
    );
    Ok(())
}
