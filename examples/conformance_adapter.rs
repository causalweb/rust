//! JSON Lines adapter for the experimental `evidence-verification-v1` runner.
//!
//! It is test tooling only. Trust arrives from the local runner invocation and
//! must not be accepted from a network request or deployment configuration.

use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    io::{self, Read},
};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use causalweb::{
    PROFILE,
    evidence::{IssuerTrust, Limits, Verifier, VerifyingKey},
};
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Deserialize)]
struct Case {
    id: String,
    compact: String,
}

#[derive(Deserialize)]
struct Trust {
    issuer: String,
    subject: String,
    audience: String,
    public_jwk: Value,
    domains: Vec<String>,
    maximum_lifetime_seconds: u64,
    clock_skew_seconds: u64,
    now: u64,
}

#[derive(Deserialize)]
struct Input {
    version: u8,
    profile: String,
    case: Case,
    trust: Trust,
}

fn key(value: &Value) -> Result<(String, VerifyingKey), Box<dyn Error>> {
    if value["kty"] != "EC" || value["crv"] != "P-256" {
        return Err("runner supplied an unsupported public key".into());
    }
    let kid = value["kid"].as_str().ok_or("runner public key lacks kid")?;
    let mut point = vec![4];
    point.extend(URL_SAFE_NO_PAD.decode(value["x"].as_str().ok_or("runner public key lacks x")?)?);
    point.extend(URL_SAFE_NO_PAD.decode(value["y"].as_str().ok_or("runner public key lacks y")?)?);
    Ok((kid.into(), VerifyingKey::from_sec1_bytes(&point)?))
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut bytes = Vec::new();
    io::stdin().take(1_048_577).read_to_end(&mut bytes)?;
    if bytes.len() > 1_048_576 {
        return Err("conformance input exceeds one megabyte".into());
    }
    let input: Input = serde_json::from_slice(&bytes)?;
    if input.version != 1 || input.profile != "evidence-verification-v1" {
        return Err("unsupported conformance profile".into());
    }
    let (kid, verifying_key) = key(&input.trust.public_jwk)?;
    let verifier = Verifier::new(
        input.trust.audience,
        vec![IssuerTrust {
            issuer: input.trust.issuer,
            keys: BTreeMap::from([(kid, verifying_key)]),
            domains: input.trust.domains.into_iter().collect::<BTreeSet<_>>(),
            max_lifetime_seconds: input.trust.maximum_lifetime_seconds,
            clock_skew_seconds: input.trust.clock_skew_seconds,
        }],
        Limits::default(),
    )?;
    let outcome = match verifier.verify(&input.case.compact, &input.trust.subject, input.trust.now)
    {
        Ok(evidence) if evidence.expired(input.trust.now) => "expired",
        Ok(evidence) if evidence.profile() == PROFILE => "accept",
        Ok(_) => "unsupported",
        Err(_) => "reject-request",
    };
    println!("{}", json!({"id":input.case.id,"outcome":outcome}));
    Ok(())
}
