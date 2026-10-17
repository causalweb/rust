//! JSON Lines adapter for the experimental `evidence-verification-v1` runner.
//!
//! It is test tooling only. Trust arrives from the local runner invocation and
//! must not be accepted from a network request or deployment configuration.

use std::{
    collections::{BTreeMap, BTreeSet},
    convert::Infallible,
    error::Error,
    io::{self, Read},
};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use causalweb::{
    CLAIM, PROFILE,
    evidence::{IssuerTrust, Limits, Verifier, VerifyingKey, retained_context_indices},
    http::{
        CONTEXT, ObservationOptions, REQUIRE, RESULT, accept_confirmation, observe, parse_context,
    },
    prefix::{Frontier, Mapping, Snapshot, evaluate, position},
};
use http::{HeaderValue, Method, Request, Response, StatusCode, header};
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

fn context_reduction_result(input: PrefixInput) -> Result<Value, Box<dyn Error>> {
    if input.version != 1 || input.profile != "context-reduction-v1" {
        return Err("unsupported conformance profile".into());
    }
    let vector = input
        .vector
        .as_object()
        .ok_or("context-reduction vector must be an object")?;
    let case = input
        .case
        .as_object()
        .ok_or("context-reduction case must be an object")?;
    let id = value_string(
        case.get("id").ok_or("context-reduction case lacks id")?,
        "context-reduction case id",
    )?;
    let evidence = case
        .get("evidence")
        .and_then(Value::as_array)
        .ok_or("context-reduction case lacks evidence")?;
    let horizon = case
        .get("required_usable_until")
        .and_then(Value::as_u64)
        .ok_or("context-reduction case lacks required usable horizon")?;
    let now = vector
        .get("assumptions")
        .and_then(Value::as_object)
        .and_then(|assumptions| assumptions.get("validation_time"))
        .and_then(Value::as_u64)
        .ok_or("context-reduction vector lacks validation time")?;
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
    let verified = evidence
        .iter()
        .enumerate()
        .map(|(index, item)| -> Result<_, Box<dyn Error>> {
            let item = item
                .as_object()
                .ok_or("context-reduction evidence must be an object")?;
            let alias = value_string(
                item.get("domain")
                    .ok_or("context-reduction evidence lacks domain")?,
                "context-reduction domain",
            )?;
            let domain = value_string(vector.get(alias).ok_or("unknown domain alias")?, "domain")?;
            let position = value_string(
                item.get("position")
                    .ok_or("context-reduction evidence lacks position")?,
                "context-reduction position",
            )?;
            let expires_at = item
                .get("exp")
                .and_then(Value::as_u64)
                .ok_or("context-reduction evidence lacks expiration")?;
            let claims = json!({
                "iss": issuer,
                "sub": subject,
                "aud": audience,
                "iat": 1,
                "exp": expires_at,
                "jti": format!("urn:context-reduction:{id}:{index}"),
                CLAIM: {
                    "v": 1,
                    "profile": PROFILE,
                    "domain": domain,
                    "position": position,
                    "commit": "stable"
                }
            });
            Ok(verifier.verify(&signed_evidence(&signing_key, &claims), subject, now)?)
        })
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    let retained_indices = retained_context_indices(&verified, now, horizon)?;
    Ok(json!({"id":id,"retained_indices":retained_indices}))
}

fn http_result(input: PrefixInput) -> Result<Value, Box<dyn Error>> {
    if input.version != 1 || input.profile != "http-client-confirmation-v1" {
        return Err("unsupported conformance profile".into());
    }
    let case = input
        .case
        .as_object()
        .ok_or("HTTP case must be an object")?;
    let id = value_string(case.get("id").ok_or("HTTP case lacks id")?, "HTTP case id")?;
    let response_input = case
        .get("response")
        .and_then(Value::as_object)
        .ok_or("HTTP case lacks response")?;
    let status = response_input
        .get("status")
        .and_then(Value::as_u64)
        .ok_or("HTTP response lacks status")?;
    let status = u16::try_from(status)?;
    if let Some(request) = case.get("request").and_then(Value::as_object) {
        if let Some(requirement) = request.get("causal_require").and_then(Value::as_str)
            && parse_context(&[requirement], Limits::default()).is_ok()
        {
            return Err("malformed requirement unexpectedly parsed".into());
        }
        if let Some(count) = request.get("evidence_count").and_then(Value::as_u64) {
            let values = std::iter::repeat_n("\"x\"", usize::try_from(count)?).collect::<Vec<_>>();
            if parse_context(&[&values.join(", ")], Limits::default()).is_ok() {
                return Err("oversized requirement set unexpectedly parsed".into());
            }
        }
    }
    let mut response = Response::new(());
    *response.status_mut() = StatusCode::from_u16(status)?;
    if let Some(value) = response_input.get("causal_result").and_then(Value::as_str) {
        response
            .headers_mut()
            .insert(RESULT, HeaderValue::from_str(value)?);
    }
    let confirmation = accept_confirmation(&response, true).is_ok();
    let mut result = serde_json::Map::from_iter([(
        "client_accepts_constrained_success".into(),
        Value::Bool(confirmation && (200..=299).contains(&status)),
    )]);
    if case.get("client_accepts_causal_confirmation").is_some() {
        result.insert(
            "client_accepts_causal_confirmation".into(),
            Value::Bool(confirmation),
        );
    }
    Ok(json!({"id":id,"result":result}))
}

fn observer_evidence(
    signing_key: &causalweb::evidence::SigningKey,
    assumptions: &serde_json::Map<String, Value>,
    id: &str,
    requirement: &serde_json::Map<String, Value>,
    index: usize,
) -> Result<String, Box<dyn Error>> {
    let issuer = value_string(
        assumptions.get("issuer").ok_or("observer lacks issuer")?,
        "issuer",
    )?;
    let subject = value_string(
        assumptions.get("subject").ok_or("observer lacks subject")?,
        "subject",
    )?;
    let audience = value_string(
        assumptions
            .get("audience")
            .ok_or("observer lacks audience")?,
        "audience",
    )?;
    let domain = value_string(
        assumptions.get("domain").ok_or("observer lacks domain")?,
        "domain",
    )?;
    let position = value_string(
        requirement
            .get("position")
            .ok_or("observer requirement lacks position")?,
        "position",
    )?;
    let expires_at = requirement
        .get("expires_at")
        .and_then(Value::as_u64)
        .unwrap_or(1000);
    let profile = requirement
        .get("profile")
        .and_then(Value::as_str)
        .unwrap_or(PROFILE);
    Ok(signed_evidence(
        signing_key,
        &json!({
            "iss": issuer,
            "sub": subject,
            "aud": audience,
            "iat": 1,
            "exp": expires_at,
            "jti": format!("urn:observer-conformance:{id}:{index}"),
            CLAIM: {
                "v": 1,
                "profile": profile,
                "domain": domain,
                "position": position,
                "commit": "stable"
            }
        }),
    ))
}

fn observer_frontier(value: &Value) -> Result<Frontier, Box<dyn Error>> {
    if value.as_str() == Some("unknown") {
        Ok(Frontier::Unknown)
    } else {
        frontier(value)
    }
}

fn observer_result(input: PrefixInput) -> Result<Value, Box<dyn Error>> {
    if input.version != 1 || input.profile != "http-observer-v1" {
        return Err("unsupported conformance profile".into());
    }
    let vector = input
        .vector
        .as_object()
        .ok_or("observer vector must be an object")?;
    let assumptions = vector
        .get("assumptions")
        .and_then(Value::as_object)
        .ok_or("observer vector lacks assumptions")?;
    let case = input
        .case
        .as_object()
        .ok_or("observer case must be an object")?;
    let id = value_string(
        case.get("id").ok_or("observer case lacks id")?,
        "observer case id",
    )?
    .to_owned();
    let request_input = case
        .get("request")
        .and_then(Value::as_object)
        .ok_or("observer case lacks request")?;
    let expected = case
        .get("expected")
        .and_then(Value::as_object)
        .ok_or("observer case lacks expected result")?;
    let issuer = value_string(
        assumptions.get("issuer").ok_or("observer lacks issuer")?,
        "issuer",
    )?;
    let audience = value_string(
        assumptions
            .get("audience")
            .ok_or("observer lacks audience")?,
        "audience",
    )?;
    let subject = value_string(
        assumptions.get("subject").ok_or("observer lacks subject")?,
        "subject",
    )?;
    let domain = value_string(
        assumptions.get("domain").ok_or("observer lacks domain")?,
        "domain",
    )?;
    let target = value_string(
        assumptions.get("target").ok_or("observer lacks target")?,
        "target",
    )?;
    let validation_time = assumptions
        .get("validation_time")
        .and_then(Value::as_u64)
        .ok_or("observer lacks validation time")?;
    let signing_key = causalweb::evidence::SigningKey::generate();
    let verifier = Verifier::new(
        audience.into(),
        vec![IssuerTrust {
            issuer: issuer.into(),
            keys: BTreeMap::from([("prefix-conformance".into(), *signing_key.verifying_key())]),
            domains: [domain.into()].into_iter().collect(),
            max_lifetime_seconds: 86_400,
            clock_skew_seconds: 0,
        }],
        Limits::default(),
    )?;
    let method = value_string(
        request_input
            .get("method")
            .ok_or("observer request lacks method")?,
        "method",
    )?
    .parse::<Method>()?;
    let mut request = Request::builder().method(method);
    if request_input.get("connection_nominates_causal") == Some(&Value::Bool(true)) {
        request = request.header(header::CONNECTION, "causal-require");
    }
    if let Some(raw) = request_input
        .get("raw_causal_require")
        .and_then(Value::as_str)
    {
        request = request.header(REQUIRE, raw);
    } else if let Some(count) = request_input
        .get("requirement_count")
        .and_then(Value::as_u64)
    {
        let values = std::iter::repeat_n("\"x\"", usize::try_from(count)?).collect::<Vec<_>>();
        request = request.header(REQUIRE, values.join(", "));
    } else {
        for (index, requirement) in request_input
            .get("requirements")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .enumerate()
        {
            let requirement = requirement
                .as_object()
                .ok_or("observer requirement must be an object")?;
            let token = observer_evidence(&signing_key, assumptions, &id, requirement, index)?;
            request = request.header(REQUIRE, format!("\"{token}\""));
        }
    }
    let request = request.body(())?;
    let state = case.get("state").and_then(Value::as_object);
    let frontiers = state
        .and_then(|state| state.get("frontiers"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(observer_frontier)
        .collect::<Result<Vec<_>, _>>()?;
    let first_terminal_failure = match state.and_then(|state| state.get("first_terminal_failure")) {
        Some(value) => Some(position(value_string(value, "observer terminal failure")?)?),
        None => None,
    };
    let progress_possible = state
        .and_then(|state| state.get("progress_possible"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let lineage = BTreeMap::from([(
        (issuer.into(), domain.into()),
        Mapping::Relevant {
            component_frontiers: frontiers,
            first_terminal_failure,
            progress_possible,
        },
    )]);
    let representation = case.get("representation").and_then(Value::as_object);
    let status = representation
        .and_then(|value| value.get("status"))
        .and_then(Value::as_u64)
        .unwrap_or(200);
    let body = representation
        .and_then(|value| value.get("body"))
        .and_then(Value::as_str)
        .unwrap_or("unused")
        .as_bytes()
        .to_vec();
    let mut response_headers = http::HeaderMap::new();
    if representation.and_then(|value| value.get("causal_context")) == Some(&Value::Bool(true)) {
        response_headers.insert(CONTEXT, HeaderValue::from_static("not-evidence"));
    }
    let mut representation_response = Response::builder()
        .status(StatusCode::from_u16(u16::try_from(status)?)?)
        .body(body)?;
    *representation_response.headers_mut() = response_headers;
    let snapshot = Snapshot::new(
        target.into(),
        representation_response,
        "contract/v1".into(),
        "schema/v1".into(),
        lineage,
    )?;
    let mut authorization_calls = 0usize;
    let mut clock_calls = 0usize;
    let mut read_calls = 0usize;
    let authorization = case.get("authorization").and_then(Value::as_str);
    let clock_after_read = case
        .get("clock_after_read")
        .and_then(Value::as_u64)
        .unwrap_or(validation_time);
    let response = observe(
        ObservationOptions {
            request: &request,
            target,
            designated_observation: case.get("designated_observation") != Some(&Value::Bool(false)),
            verifier: &verifier,
            authenticated_subject: subject,
        },
        || {
            authorization_calls += 1;
            Ok::<bool, Infallible>(
                authorization != Some("deny-before-read")
                    && !(authorization == Some("deny-before-response") && authorization_calls > 1),
            )
        },
        || {
            clock_calls += 1;
            if clock_calls == 1 {
                validation_time
            } else {
                clock_after_read
            }
        },
        || {
            read_calls += 1;
            Ok::<_, Infallible>(snapshot)
        },
    )
    .unwrap_or_else(|error| error.into_response());
    let body = std::str::from_utf8(response.body())?.to_owned();
    let mut result = serde_json::Map::from_iter([
        ("status".into(), json!(response.status().as_u16())),
        (
            "causal_result".into(),
            response
                .headers()
                .get(RESULT)
                .and_then(|value| value.to_str().ok())
                .map_or(Value::Null, |value| json!(value)),
        ),
        (
            "cache_control".into(),
            response
                .headers()
                .get(header::CACHE_CONTROL)
                .and_then(|value| value.to_str().ok())
                .map_or(Value::Null, |value| json!(value)),
        ),
        ("read_calls".into(), json!(read_calls)),
    ]);
    if expected.contains_key("vary_contains_causal_require") {
        let contains = response
            .headers()
            .get_all(header::VARY)
            .iter()
            .any(|value| {
                value.to_str().is_ok_and(|value| {
                    value
                        .split(',')
                        .any(|value| value.trim().eq_ignore_ascii_case("causal-require"))
                })
            });
        result.insert("vary_contains_causal_require".into(), json!(contains));
    }
    if expected.contains_key("context_removed") {
        result.insert(
            "context_removed".into(),
            json!(!response.headers().contains_key(CONTEXT)),
        );
    }
    if expected.contains_key("body") {
        result.insert("body".into(), json!(body));
    }
    if expected.contains_key("outcomes") {
        result.insert(
            "outcomes".into(),
            serde_json::from_str::<Value>(&body)?["outcomes"].clone(),
        );
    }
    Ok(json!({"id":id,"result":result}))
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
    if profile == "context-reduction-v1" {
        println!(
            "{}",
            context_reduction_result(serde_json::from_value(raw)?)?
        );
        return Ok(());
    }
    if profile == "http-client-confirmation-v1" {
        println!("{}", http_result(serde_json::from_value(raw)?)?);
        return Ok(());
    }
    if profile == "http-observer-v1" {
        println!("{}", observer_result(serde_json::from_value(raw)?)?);
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
