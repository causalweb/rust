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
    CLAIM, PROFILE,
    evidence::{IssuerTrust, Limits, Verifier, VerifyingKey},
    prefix::{Frontier, Mapping, Snapshot, evaluate, position},
};
use p256::ecdsa::{Signature, signature::Signer};
use p256::elliptic_curve::Generate;
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

#[derive(Deserialize)]
struct PrefixInput {
    version: u8,
    profile: String,
    vector: Value,
    case: Value,
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

fn value_string<'a>(value: &'a Value, name: &str) -> Result<&'a str, Box<dyn Error>> {
    value
        .as_str()
        .filter(|string| !string.is_empty())
        .ok_or_else(|| format!("{name} must be a nonempty string").into())
}

fn signed_evidence(key: &causalweb::evidence::SigningKey, claims: &Value) -> String {
    let header = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(
            &json!({"alg":"ES256","kid":"prefix-conformance","typ":"cw-evidence+jwt"}),
        )
        .expect("static header serializes"),
    );
    let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).expect("claims serialize"));
    let input = format!("{header}.{payload}");
    let signature: Signature = key.sign(input.as_bytes());
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()))
}

fn contains_alias(value: &Value, alias: &str) -> bool {
    value
        .as_array()
        .is_some_and(|items| items.iter().any(|item| item.as_str() == Some(alias)))
}

fn frontier(value: &Value) -> Result<Frontier, Box<dyn Error>> {
    if value.is_null() {
        Ok(Frontier::Bottom)
    } else {
        Ok(Frontier::At(position(value_string(value, "frontier")?)?))
    }
}

fn prefix_result(input: PrefixInput) -> Result<Value, Box<dyn Error>> {
    if input.version != 1 || input.profile != "prefix-evaluation-v1" {
        return Err("unsupported conformance profile".into());
    }
    let vector = input
        .vector
        .as_object()
        .ok_or("prefix vector must be an object")?;
    let case = input
        .case
        .as_object()
        .ok_or("prefix case must be an object")?;
    let id = value_string(
        case.get("id").ok_or("prefix case lacks id")?,
        "prefix case id",
    )?;
    if case.get("kind").and_then(Value::as_str) == Some("position-validation") {
        let outcome = if position(value_string(
            case.get("position").ok_or("position case lacks position")?,
            "position",
        )?)
        .is_ok()
        {
            "accept"
        } else {
            "reject-request"
        };
        return Ok(json!({"id":id,"outcome":outcome}));
    }
    if case.get("kind").and_then(Value::as_str) == Some("position-validation-and-comparison") {
        let required = case
            .get("position")
            .and_then(Value::as_str)
            .and_then(|value| position(value).ok());
        let actual = case
            .get("frontier")
            .and_then(Value::as_str)
            .and_then(|value| position(value).ok());
        let outcome = match (required, actual) {
            (Some(required), Some(actual)) if actual >= required => "satisfied",
            (Some(_), Some(_)) => "unsatisfied",
            _ => "reject-request",
        };
        return Ok(json!({"id":id,"outcome":outcome}));
    }
    let requirements = case
        .get("requirements")
        .and_then(Value::as_array)
        .ok_or("prefix case lacks requirements")?;
    let state = case
        .get("state")
        .and_then(Value::as_object)
        .ok_or("prefix case lacks state")?;
    let issuer = "https://issuer.example";
    let audience = "https://verifier.example/causal";
    let subject = "opaque-tenant";
    let domain_a = value_string(
        vector.get("domain_a").ok_or("vector lacks domain_a")?,
        "domain_a",
    )?;
    let domain_b = value_string(
        vector.get("domain_b").ok_or("vector lacks domain_b")?,
        "domain_b",
    )?;
    let signing_key = causalweb::evidence::SigningKey::generate();
    let verifier = Verifier::new(
        audience.into(),
        vec![IssuerTrust {
            issuer: issuer.into(),
            keys: BTreeMap::from([("prefix-conformance".into(), *signing_key.verifying_key())]),
            domains: [domain_a.into(), domain_b.into()].into_iter().collect(),
            max_lifetime_seconds: 86_400,
            clock_skew_seconds: 0,
        }],
        Limits::default(),
    )?;
    let mut outcomes = Vec::new();
    for requirement in requirements {
        let requirement = requirement
            .as_object()
            .ok_or("requirement must be an object")?;
        let alias = value_string(
            requirement
                .get("domain")
                .ok_or("requirement lacks domain")?,
            "domain",
        )?;
        let domain = value_string(vector.get(alias).ok_or("unknown domain alias")?, "domain")?;
        let requirement_position = value_string(
            requirement
                .get("position")
                .ok_or("requirement lacks position")?,
            "position",
        )?;
        let expires_at = requirement
            .get("expires_at")
            .and_then(Value::as_u64)
            .unwrap_or(1000);
        let profile = if requirement.get("profile_supported") == Some(&Value::Bool(false)) {
            "urn:test:unknown-profile"
        } else {
            PROFILE
        };
        let mut claims = json!({
            "iss":issuer,
            "sub":subject,
            "aud":audience,
            "iat":1,
            "exp":expires_at,
            "jti":format!("urn:prefix-conformance:{id}:{alias}"),
        });
        claims[CLAIM] = json!({
            "v":1,
            "profile":profile,
            "domain":domain,
            "position":requirement_position,
            "commit":"stable",
        });
        let evidence = verifier.verify(&signed_evidence(&signing_key, &claims), subject, 100)?;
        let mut lineage = BTreeMap::new();
        let configured = state
            .get("configured_domains")
            .is_none_or(|configured| contains_alias(configured, alias));
        if configured {
            if state
                .get("authorized_exclusions")
                .is_some_and(|exclusions| contains_alias(exclusions, alias))
            {
                lineage.insert(
                    (issuer.into(), domain.into()),
                    Mapping::Excluded {
                        first_position: 0,
                        last_position: u64::MAX,
                    },
                );
            } else {
                let selected = state
                    .get("selected_state_frontiers")
                    .or_else(|| state.get("frontiers"))
                    .and_then(Value::as_object);
                let components = state
                    .get("component_frontiers")
                    .and_then(Value::as_object)
                    .and_then(|all| all.get(alias))
                    .and_then(Value::as_array);
                let component_frontiers = if let Some(components) = components {
                    components
                        .iter()
                        .map(frontier)
                        .collect::<Result<Vec<_>, _>>()?
                } else if state.get("lineage_available") == Some(&Value::Bool(false)) {
                    vec![Frontier::Unknown]
                } else if let Some(value) = selected.and_then(|frontiers| frontiers.get(alias)) {
                    vec![frontier(value)?]
                } else {
                    vec![Frontier::Unknown]
                };
                let first_terminal_failure = state
                    .get("terminal_failures")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter(|failure| failure.get("domain").and_then(Value::as_str) == Some(alias))
                    .map(|failure| -> Result<u64, Box<dyn Error>> {
                        Ok(position(value_string(
                            failure
                                .get("position")
                                .ok_or("terminal failure lacks position")?,
                            "terminal failure position",
                        )?)?)
                    })
                    .collect::<Result<Vec<_>, _>>()?
                    .into_iter()
                    .min();
                lineage.insert(
                    (issuer.into(), domain.into()),
                    Mapping::Relevant {
                        component_frontiers,
                        first_terminal_failure,
                        progress_possible: true,
                    },
                );
            }
        }
        let snapshot = Snapshot::new(
            "/orders/123".into(),
            (),
            "contract/v1".into(),
            "schema/v1".into(),
            lineage,
        )?;
        let evaluation = evaluate(&evidence, &snapshot, 100);
        let mut outcome = serde_json::to_value(evaluation)?;
        outcome
            .as_object_mut()
            .ok_or("evaluation must serialize to object")?
            .remove("retryable");
        outcomes.push(outcome);
    }
    let aggregate_success = outcomes
        .iter()
        .all(|outcome| outcome.get("outcome") == Some(&Value::String("satisfied".into())));
    Ok(json!({"id":id,"outcomes":outcomes,"aggregate_success":aggregate_success}))
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut bytes = Vec::new();
    io::stdin().take(1_048_577).read_to_end(&mut bytes)?;
    if bytes.len() > 1_048_576 {
        return Err("conformance input exceeds one megabyte".into());
    }
    let raw: Value = serde_json::from_slice(&bytes)?;
    let profile = value_string(raw.get("profile").ok_or("input lacks profile")?, "profile")?;
    if profile == "prefix-evaluation-v1" {
        println!("{}", prefix_result(serde_json::from_value(raw)?)?);
        return Ok(());
    }
    let input: Input = serde_json::from_value(raw)?;
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
