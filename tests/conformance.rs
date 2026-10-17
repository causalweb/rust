mod common;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use causalweb::{
    CLAIM,
    evidence::{IssuerTrust, SigningKey, Verifier, VerifyingKey, retained_context_indices},
    http as cw_http,
    prefix::{self, Frontier, Mapping, Snapshot},
};
use common::*;
use http::{HeaderValue, Request, Response};
use p256::elliptic_curve::Generate;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

#[test]
fn all_pinned_jws_vectors() {
    let file: Value = serde_json::from_str(include_str!("vectors/jws-evidence.json")).unwrap();
    let jwk = &file["public_jwk"];
    let mut point = vec![4];
    point.extend(URL_SAFE_NO_PAD.decode(jwk["x"].as_str().unwrap()).unwrap());
    point.extend(URL_SAFE_NO_PAD.decode(jwk["y"].as_str().unwrap()).unwrap());
    let key = VerifyingKey::from_sec1_bytes(&point).unwrap();
    let verifier = Verifier::new(
        file["expected_audience"].as_str().unwrap().into(),
        vec![IssuerTrust {
            issuer: ISSUER.into(),
            keys: BTreeMap::from([(jwk["kid"].as_str().unwrap().into(), key)]),
            domains: BTreeSet::from(["https://issuer.example/domains/orders/2026".into()]),
            max_lifetime_seconds: 86400,
            clock_skew_seconds: 0,
        }],
        limits(),
    )
    .unwrap();
    let now = file["validation_time"].as_u64().unwrap();
    let cases = file["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 6);
    for case in cases {
        let actual = verifier.verify(
            case["compact"].as_str().unwrap(),
            file["expected_subject"].as_str().unwrap(),
            now,
        );
        match case["expected"].as_str().unwrap() {
            "accept" => assert!(!actual.unwrap().expired(now), "{}", case["id"]),
            "expired" => assert!(actual.unwrap().expired(now), "{}", case["id"]),
            "reject-request" => assert!(actual.is_err(), "{}", case["id"]),
            _ => panic!("unrecognized fixture expectation"),
        }
    }
}

#[test]
fn all_pinned_security_vectors_from_an_independent_signer() {
    let file: Value =
        serde_json::from_str(include_str!("vectors/evidence-validation.json")).unwrap();
    let jwk = &file["public_jwk"];
    let mut point = vec![4];
    point.extend(URL_SAFE_NO_PAD.decode(jwk["x"].as_str().unwrap()).unwrap());
    point.extend(URL_SAFE_NO_PAD.decode(jwk["y"].as_str().unwrap()).unwrap());
    let verifier = Verifier::new(
        file["expected_audience"].as_str().unwrap().into(),
        vec![IssuerTrust {
            issuer: file["expected_issuer"].as_str().unwrap().into(),
            keys: BTreeMap::from([(
                jwk["kid"].as_str().unwrap().into(),
                VerifyingKey::from_sec1_bytes(&point).unwrap(),
            )]),
            domains: file["authorized_domains"]
                .as_array()
                .unwrap()
                .iter()
                .map(|d| d.as_str().unwrap().into())
                .collect(),
            max_lifetime_seconds: file["max_lifetime_seconds"].as_u64().unwrap(),
            clock_skew_seconds: file["clock_skew_seconds"].as_u64().unwrap(),
        }],
        limits(),
    )
    .unwrap();
    let now = file["validation_time"].as_u64().unwrap();
    let state = snapshot((), vec![Frontier::At(5)]);
    assert_eq!(file["cases"].as_array().unwrap().len(), 26);
    for case in file["cases"].as_array().unwrap() {
        let actual = verifier.verify(
            case["compact"].as_str().unwrap(),
            file["expected_subject"].as_str().unwrap(),
            now,
        );
        match case["expected"].as_str().unwrap() {
            "reject-request" => assert!(actual.is_err(), "{} {}", case["id"], case["description"]),
            "accept" => assert_eq!(
                prefix::evaluate(&actual.unwrap(), &state, now).outcome,
                prefix::Outcome::Satisfied,
                "{}",
                case["id"]
            ),
            expected => assert_eq!(
                json!(prefix::evaluate(&actual.unwrap(), &state, now).outcome),
                expected,
                "{}",
                case["id"]
            ),
        }
    }
}

fn frontier(value: &Value) -> Frontier {
    if value.is_null() {
        Frontier::Bottom
    } else {
        Frontier::At(prefix::position(value.as_str().unwrap()).unwrap())
    }
}

#[test]
fn all_pinned_prefix_vectors() {
    let vectors: Value =
        serde_json::from_str(include_str!("vectors/prefix-evaluation.json")).unwrap();
    let key = SigningKey::generate();
    let verifier = verifier(*key.verifying_key());
    let cases = vectors["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 20);
    for case in cases {
        let kind = case["kind"].as_str().unwrap_or("");
        if kind.starts_with("position-validation") {
            let actual = prefix::position(case["position"].as_str().unwrap());
            if case["expected"] == "reject-request" {
                assert!(actual.is_err(), "{}", case["id"]);
            } else {
                assert!(
                    prefix::position(case["frontier"].as_str().unwrap()).unwrap()
                        >= actual.unwrap()
                );
            }
            continue;
        }
        if kind == "context-reduction" {
            let evidence: Vec<_> = case["evidence"]
                .as_array()
                .unwrap()
                .iter()
                .enumerate()
                .map(|(index, item)| {
                    let alias = item["domain"].as_str().unwrap();
                    let mut fact = claims(item["position"].as_str().unwrap());
                    fact[CLAIM]["domain"] = vectors[alias].clone();
                    fact["exp"] = item["exp"].clone();
                    fact["jti"] = json!(format!("urn:test:context:{}:{index}", case["id"]));
                    verifier.verify(&sign(&key, &fact), SUBJECT, 100).unwrap()
                })
                .collect();
            let retained: Vec<_> = retained_context_indices(
                &evidence,
                100,
                case["required_usable_until"].as_u64().unwrap(),
            )
            .unwrap()
            .into_iter()
            .map(|index| json!(evidence[index].position()))
            .collect();
            assert!(
                case["allowed_retained_positions"]
                    .as_array()
                    .unwrap()
                    .contains(&json!(retained)),
                "{}",
                case["id"]
            );
            continue;
        }
        let state = &case["state"];
        let mut outcomes = Vec::new();
        for req in case["requirements"].as_array().unwrap() {
            let domain_alias = req["domain"].as_str().unwrap();
            let domain = vectors[domain_alias].as_str().unwrap();
            let mut claims = claims(req["position"].as_str().unwrap());
            claims[CLAIM]["domain"] = json!(domain);
            if req["profile_supported"] == false {
                claims[CLAIM]["profile"] = json!("urn:test:unknown-profile");
            }
            claims["exp"] = req.get("expires_at").cloned().unwrap_or(json!(1000));
            let evidence = verifier.verify(&sign(&key, &claims), SUBJECT, 100).unwrap();
            let mut lineage = BTreeMap::new();
            let configured = state["configured_domains"]
                .as_array()
                .is_none_or(|d| d.contains(&json!(domain_alias)));
            if configured {
                let mapping = if state["authorized_exclusions"]
                    .as_array()
                    .is_some_and(|d| d.contains(&json!(domain_alias)))
                {
                    Mapping::Excluded {
                        first_position: 0,
                        last_position: u64::MAX,
                    }
                } else {
                    let frontiers = state
                        .get("selected_state_frontiers")
                        .or_else(|| state.get("frontiers"));
                    let components = if let Some(values) =
                        state["component_frontiers"][domain_alias].as_array()
                    {
                        values.iter().map(frontier).collect()
                    } else if state["lineage_available"] == false {
                        vec![Frontier::Unknown]
                    } else if let Some(f) = frontiers.and_then(|fs| fs.get(domain_alias)) {
                        vec![frontier(f)]
                    } else {
                        vec![Frontier::Unknown]
                    };
                    let failure = state["terminal_failures"].as_array().and_then(|f| {
                        f.iter()
                            .filter(|f| f["domain"] == domain_alias)
                            .map(|f| prefix::position(f["position"].as_str().unwrap()).unwrap())
                            .min()
                    });
                    Mapping::Relevant {
                        component_frontiers: components,
                        first_terminal_failure: failure,
                        progress_possible: true,
                    }
                };
                lineage.insert((ISSUER.into(), domain.into()), mapping);
            }
            let snapshot = Snapshot::new(
                TARGET.into(),
                (),
                "contract/v1".into(),
                "schema/v1".into(),
                lineage,
            )
            .unwrap();
            let outcome = prefix::evaluate(&evidence, &snapshot, 100);
            let mut semantic = json!({"outcome":outcome.outcome});
            if let Some(disposition) = outcome.disposition {
                semantic["disposition"] = json!(disposition);
            }
            outcomes.push(semantic);
        }
        assert_eq!(json!(outcomes), case["expected"], "{}", case["id"]);
        assert_eq!(
            outcomes.iter().all(|v| v["outcome"] == "satisfied"),
            case["aggregate_success"].as_bool().unwrap(),
            "{}",
            case["id"]
        );
    }
}

#[test]
fn carrier_reduction_preserves_non_dominant_evidence() {
    let key = SigningKey::generate();
    let verifier = verifier(*key.verifying_key());
    let evidence = |position: &str, expires_at: u64, domain: &str| {
        let mut fact = claims(position);
        fact["exp"] = json!(expires_at);
        fact[CLAIM]["domain"] = json!(domain);
        verifier.verify(&sign(&key, &fact), SUBJECT, 100).unwrap()
    };
    let lower = evidence("5", 300, DOMAIN);
    let higher = evidence("8", 300, DOMAIN);
    assert_eq!(
        retained_context_indices(&[lower, higher], 100, 180),
        Ok(vec![1])
    );
    let lower = evidence("5", 300, DOMAIN);
    let short_lived_higher = evidence("8", 150, DOMAIN);
    assert_eq!(
        retained_context_indices(&[lower, short_lived_higher], 100, 180),
        Ok(vec![0, 1])
    );
    let lower = evidence("5", 300, DOMAIN);
    let other_domain = evidence("8", 300, OTHER_DOMAIN);
    assert_eq!(
        retained_context_indices(&[lower, other_domain], 100, 180),
        Ok(vec![0, 1])
    );
}

#[test]
fn all_pinned_http_vectors() {
    let vectors: Value = serde_json::from_str(include_str!("vectors/http-outcomes.json")).unwrap();
    let cases = vectors["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 12);
    for case in cases {
        let status = case["response"]["status"].as_u64().unwrap() as u16;
        let mut response = Response::builder().status(status).body(()).unwrap();
        if let Some(result) = case["response"]["causal_result"].as_str() {
            response
                .headers_mut()
                .insert(cw_http::RESULT, HeaderValue::from_str(result).unwrap());
        }
        let confirmed = cw_http::accept_confirmation(&response, true).is_ok();
        assert_eq!(
            confirmed && (200..=299).contains(&status),
            case["client_accepts_constrained_success"]
                .as_bool()
                .unwrap(),
            "{}",
            case["id"]
        );
        if let Some(expected) = case["client_accepts_causal_confirmation"].as_bool() {
            assert_eq!(confirmed, expected);
        }
        if let Some(field) = case["request"]["causal_require"].as_str() {
            assert!(cw_http::parse_context(&[field], limits()).is_err());
        }
        if case["id"] == "HTTP-008" {
            let values = vec!["\"opaque\""; 17].join(", ");
            assert_eq!(
                cw_http::parse_context(&[&values], limits()).unwrap_err(),
                causalweb::Error::TooLarge
            );
        }
    }
}

#[test]
fn issuer_to_observer_to_client_exchange() {
    let key = SigningKey::generate();
    let verifier = verifier(*key.verifying_key());
    let issuer = issuer(key);
    let token = issuer.issue_committed(&committed(5), 100).unwrap();
    let mut request = Request::new(());
    *request.headers_mut() = cw_http::request_headers(&[token], limits()).unwrap();
    let stale = cw_http::observe::<_, _, _, (), ()>(
        cw_http::ObservationOptions {
            request: &request,
            target: TARGET,
            designated_observation: true,
            verifier: &verifier,
            authenticated_subject: SUBJECT,
        },
        || Ok::<_, ()>(true),
        || 100,
        || {
            Ok(snapshot(
                Response::new(b"stale".to_vec()),
                vec![Frontier::At(4)],
            ))
        },
    )
    .unwrap_or_else(cw_http::ObservationError::into_response);
    assert_eq!(stale.status(), 412);
    assert!(cw_http::accept_confirmation(&stale, true).is_err());
    let current = cw_http::observe::<_, _, _, (), ()>(
        cw_http::ObservationOptions {
            request: &request,
            target: TARGET,
            designated_observation: true,
            verifier: &verifier,
            authenticated_subject: SUBJECT,
        },
        || Ok::<_, ()>(true),
        || 100,
        || {
            Ok(snapshot(
                Response::new(b"indexed".to_vec()),
                vec![Frontier::At(5)],
            ))
        },
    )
    .unwrap_or_else(cw_http::ObservationError::into_response);
    assert_eq!(current.status(), 200);
    assert_eq!(current.body(), b"indexed");
    assert_eq!(current.headers()["cache-control"], "private, no-store");
    assert_eq!(current.headers()["vary"], "Causal-Require");
    cw_http::accept_confirmation(&current, true).unwrap();
}
