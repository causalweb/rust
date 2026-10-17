mod common;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use causalweb::{
    CLAIM, Error,
    evidence::SigningKey,
    http as cw_http,
    prefix::{self, Frontier, Mapping, Outcome, Snapshot},
};
use common::*;
use http::{HeaderValue, Request, Response};
use p256::elliptic_curve::Generate;
use serde_json::json;
use std::{cell::Cell, collections::BTreeMap};

#[test]
fn trust_and_lifetime_fail_closed() {
    let key = SigningKey::generate();
    let verifier = verifier(*key.verifying_key());
    let token = sign(&key, &claims("5"));
    assert!(verifier.verify(&token, "different-tenant", 100).is_err());
    assert!(verifier.verify(&token, "", 100).is_err());
    let other_key = SigningKey::generate();
    assert!(
        verifier
            .verify(&sign(&other_key, &claims("5")), SUBJECT, 100)
            .is_err()
    );
    for (field, value) in [
        ("aud", json!("other-audience")),
        ("aud", json!([AUDIENCE, AUDIENCE])),
        ("aud", json!([AUDIENCE, ""])),
        ("nbf", json!(0)),
        ("iat", json!(101)),
        ("exp", json!(1)),
        ("exp", json!(9007199254740992u64)),
        ("exp", json!(90000)),
    ] {
        let mut c = claims("5");
        c[field] = value;
        assert!(
            verifier.verify(&sign(&key, &c), SUBJECT, 100).is_err(),
            "{field}"
        );
    }
    let mut wrong_domain = claims("5");
    wrong_domain[CLAIM]["domain"] = json!("https://untrusted.example/domain");
    assert!(
        verifier
            .verify(&sign(&key, &wrong_domain), SUBJECT, 100)
            .is_err()
    );
    let mut different_case = claims("5");
    different_case["iss"] = json!("https://ISSUER.example");
    assert!(
        verifier
            .verify(&sign(&key, &different_case), SUBJECT, 100)
            .is_err()
    );
    let expired = verifier.verify(&token, SUBJECT, 1000).unwrap();
    assert!(expired.expired(1000));
    let skewed = verifier_with(*key.verifying_key(), limits(), 5);
    assert!(!skewed.verify(&token, SUBJECT, 1004).unwrap().expired(1004));
    assert!(skewed.verify(&token, SUBJECT, 1005).unwrap().expired(1005));
    assert!(
        skewed
            .verify(&token, SUBJECT, u64::MAX)
            .unwrap()
            .expired(u64::MAX)
    );
}

#[test]
fn duplicate_names_are_rejected_at_every_depth() {
    let key = SigningKey::generate();
    let verifier = verifier(*key.verifying_key());
    for extra in [
        r#", "extension":{"x":1,"x":2}"#,
        r#", "extension":[{"x":1,"\u0078":2}]"#,
        r#", "\u0069ss":"https://issuer.example""#,
    ] {
        let mut payload = serde_json::to_string(&claims("5")).unwrap();
        payload.pop();
        payload.push_str(extra);
        payload.push('}');
        let compact = sign_bytes(
            &key,
            &serde_json::to_vec(&header()).unwrap(),
            payload.as_bytes(),
        );
        assert_eq!(
            verifier.verify(&compact, SUBJECT, 100).err(),
            Some(Error::InvalidEvidence)
        );
    }
    let bad_header = br#"{"alg":"ES256","alg":"ES256","kid":"test-key","typ":"cw-evidence+jwt"}"#;
    assert!(
        verifier
            .verify(
                &sign_bytes(&key, bad_header, &serde_json::to_vec(&claims("5")).unwrap()),
                SUBJECT,
                100
            )
            .is_err()
    );
}

#[test]
fn encodings_extensions_and_depth_are_bounded() {
    let key = SigningKey::generate();
    let verifier = verifier(*key.verifying_key());
    let token = sign(&key, &claims("5"));
    for extension in ["crit", "b64", "jku", "x5u", "zip"] {
        let mut h = header();
        h[extension] = json!("https://attacker.invalid/key");
        assert!(
            verifier
                .verify(
                    &sign_bytes(
                        &key,
                        &serde_json::to_vec(&h).unwrap(),
                        &serde_json::to_vec(&claims("5")).unwrap()
                    ),
                    SUBJECT,
                    100
                )
                .is_err()
        );
    }
    let mut segments: Vec<_> = token.split('.').map(str::to_owned).collect();
    segments[0].push('=');
    assert!(verifier.verify(&segments.join("."), SUBJECT, 100).is_err());
    let mut segments: Vec<_> = token.split('.').map(str::to_owned).collect();
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let last = segments[2].pop().unwrap();
    let index = alphabet.iter().position(|b| *b == last as u8).unwrap();
    segments[2].push(alphabet[index + 1] as char);
    assert!(URL_SAFE_NO_PAD.decode(&segments[2]).is_err());
    assert!(verifier.verify(&segments.join("."), SUBJECT, 100).is_err());
    let mut bom = b"\xef\xbb\xbf".to_vec();
    bom.extend(serde_json::to_vec(&claims("5")).unwrap());
    assert!(
        verifier
            .verify(
                &sign_bytes(&key, &serde_json::to_vec(&header()).unwrap(), &bom),
                SUBJECT,
                100
            )
            .is_err()
    );
    assert!(
        verifier
            .verify(
                &sign_bytes(&key, &serde_json::to_vec(&header()).unwrap(), b"\xff"),
                SUBJECT,
                100
            )
            .is_err()
    );
    let mut c = claims("5");
    c["extension"] = json!({"nested":[1,true,"ignored"]});
    assert!(verifier.verify(&sign(&key, &c), SUBJECT, 100).is_ok());
    let mut nested = json!(0);
    for _ in 0..33 {
        nested = json!([nested]);
    }
    c["extension"] = nested;
    assert!(verifier.verify(&sign(&key, &c), SUBJECT, 100).is_err());
    let mut bounded = limits();
    bounded.max_token_bytes = 4;
    assert_eq!(
        verifier_with(*key.verifying_key(), bounded, 0)
            .verify(&token, SUBJECT, 100)
            .err(),
        Some(Error::TooLarge)
    );
}

#[test]
fn numeric_dates_are_exact_not_floats() {
    let key = SigningKey::generate();
    let verifier = verifier(*key.verifying_key());
    let h = serde_json::to_vec(&header()).unwrap();
    let payload = serde_json::to_string(&claims("5")).unwrap();
    for iat in ["1.0", "1e0", "100e-2", "0.1e1"] {
        let raw = payload.replace("\"iat\":1", &format!("\"iat\":{iat}"));
        assert!(
            verifier
                .verify(&sign_bytes(&key, &h, raw.as_bytes()), SUBJECT, 100)
                .is_ok(),
            "{iat}"
        );
    }
    for iat in ["1.5", "9007199254740990.5", "1e9999", "-1", "1e-9999"] {
        let raw = payload.replace("\"iat\":1", &format!("\"iat\":{iat}"));
        assert!(
            verifier
                .verify(&sign_bytes(&key, &h, raw.as_bytes()), SUBJECT, 100)
                .is_err(),
            "{iat}"
        );
    }
}

#[test]
fn expiry_precedes_unsupported_but_not_validation_errors() {
    let key = SigningKey::generate();
    let verifier = verifier(*key.verifying_key());
    let state = snapshot((), vec![Frontier::At(9)]);
    let mut c = claims("opaque");
    c[CLAIM]["profile"] = json!("urn:test:unknown");
    c["exp"] = json!(100);
    let evidence = verifier.verify(&sign(&key, &c), SUBJECT, 100).unwrap();
    assert_eq!(
        prefix::evaluate(&evidence, &state, 100).outcome,
        Outcome::Expired
    );
    c["exp"] = json!(1000);
    let evidence = verifier.verify(&sign(&key, &c), SUBJECT, 100).unwrap();
    assert_eq!(
        prefix::evaluate(&evidence, &state, 100).outcome,
        Outcome::Unsupported
    );
    c[CLAIM]["profile"] = json!(causalweb::PROFILE);
    c[CLAIM]["position"] = json!("05");
    c["exp"] = json!(100);
    assert!(verifier.verify(&sign(&key, &c), SUBJECT, 100).is_err());
}

fn request(token: &str) -> Request<()> {
    let mut request = Request::new(());
    *request.headers_mut() = cw_http::request_headers(&[token.into()], limits()).unwrap();
    request
}

#[test]
fn validation_happens_before_state_selection_and_errors_do_not_leak() {
    let key = SigningKey::generate();
    let verifier = verifier(*key.verifying_key());
    let read = Cell::new(false);
    let response = cw_http::observe(
        &request("not-a-jws"),
        TARGET,
        true,
        &verifier,
        SUBJECT,
        || true,
        || 100,
        || {
            read.set(true);
            Ok(snapshot(Response::new(vec![]), vec![Frontier::At(5)]))
        },
    );
    assert!(!read.get());
    assert_eq!(response.status(), 400);
    assert!(!response.headers().contains_key(cw_http::RESULT));
    let body = String::from_utf8(response.body().clone()).unwrap();
    assert!(!body.contains("outcomes"));
    assert!(!body.contains(ISSUER));
    assert!(!body.contains("not-a-jws"));
}

#[test]
fn expiry_and_authorization_are_rechecked_after_read() {
    let key = SigningKey::generate();
    let verifier = verifier(*key.verifying_key());
    let mut c = claims("5");
    c["exp"] = json!(101);
    let req = request(&sign(&key, &c));
    let calls = Cell::new(0);
    let response = cw_http::observe(
        &req,
        TARGET,
        true,
        &verifier,
        SUBJECT,
        || true,
        || {
            calls.set(calls.get() + 1);
            if calls.get() == 1 { 100 } else { 101 }
        },
        || {
            Ok(snapshot(
                Response::new(b"must not escape".to_vec()),
                vec![Frontier::At(5)],
            ))
        },
    );
    assert_eq!(response.status(), 412);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(response.body()).unwrap()["outcomes"][0]["outcome"],
        "expired"
    );
    let checks = Cell::new(0);
    let response = cw_http::observe(
        &req,
        TARGET,
        true,
        &verifier,
        SUBJECT,
        || {
            checks.set(checks.get() + 1);
            checks.get() == 1
        },
        || 100,
        || {
            Ok(snapshot(
                Response::new(b"must not escape".to_vec()),
                vec![Frontier::At(5)],
            ))
        },
    );
    assert_eq!(response.status(), 403);
    assert!(response.body().is_empty());
    assert!(!response.headers().contains_key(cw_http::RESULT));
}

#[test]
fn ordered_duplicates_limits_and_method_checks() {
    let key = SigningKey::generate();
    let verifier = verifier(*key.verifying_key());
    let token = sign(&key, &claims("5"));
    let req = {
        let mut r = Request::new(());
        *r.headers_mut() =
            cw_http::request_headers(&[token.clone(), token.clone()], limits()).unwrap();
        r
    };
    let response = cw_http::observe(
        &req,
        TARGET,
        true,
        &verifier,
        SUBJECT,
        || true,
        || 100,
        || Ok(snapshot(Response::new(vec![]), vec![Frontier::Bottom])),
    );
    let body: serde_json::Value = serde_json::from_slice(response.body()).unwrap();
    assert_eq!(body["outcomes"].as_array().unwrap().len(), 2);
    assert_eq!(body["outcomes"][0]["index"], 0);
    assert_eq!(body["outcomes"][1]["index"], 1);
    let mut oversized = request(&token);
    oversized.headers_mut().insert(
        cw_http::REQUIRE,
        HeaderValue::from_str(&vec!["\"x\""; 17].join(", ")).unwrap(),
    );
    let response = cw_http::observe(
        &oversized,
        TARGET,
        true,
        &verifier,
        SUBJECT,
        || true,
        || 100,
        || panic!("must not read"),
    );
    assert_eq!(response.status(), 431);
    assert!(!response.headers().contains_key(cw_http::RESULT));
    let mut head = request(&token);
    *head.method_mut() = http::Method::HEAD;
    assert_eq!(
        cw_http::observe(
            &head,
            TARGET,
            true,
            &verifier,
            SUBJECT,
            || true,
            || 100,
            || panic!("must not read")
        )
        .status(),
        400
    );
    assert_eq!(
        cw_http::observe(
            &request(&token),
            TARGET,
            false,
            &verifier,
            SUBJECT,
            || true,
            || 100,
            || panic!("must not read")
        )
        .status(),
        400
    );
}

#[test]
fn mappings_and_all_components_are_required() {
    let key = SigningKey::generate();
    let verifier = verifier(*key.verifying_key());
    let evidence = verifier
        .verify(&sign(&key, &claims("5")), SUBJECT, 100)
        .unwrap();
    let state = snapshot((), vec![Frontier::At(10), Frontier::Unknown]);
    assert_eq!(
        prefix::evaluate(&evidence, &state, 100).outcome,
        Outcome::Unknown
    );
    let state =
        Snapshot::new(TARGET.into(), (), "v1".into(), "v1".into(), BTreeMap::new()).unwrap();
    assert_eq!(
        prefix::evaluate(&evidence, &state, 100).outcome,
        Outcome::Unsupported
    );
    let mapping = BTreeMap::from([(
        (ISSUER.into(), DOMAIN.into()),
        Mapping::Excluded {
            first_position: 0,
            last_position: 4,
        },
    )]);
    let state = Snapshot::new(TARGET.into(), (), "v1".into(), "v1".into(), mapping).unwrap();
    assert_eq!(
        prefix::evaluate(&evidence, &state, 100).outcome,
        Outcome::Unknown
    );
}

#[test]
fn structured_fields_and_client_confirmation_are_strict() {
    for field in [
        "",
        "()",
        "token",
        "123",
        "\"x\";a",
        "\"x\",",
        "\"unterminated",
        "\"bad\\escape\"",
    ] {
        assert!(
            cw_http::parse_context(&[field], limits()).is_err(),
            "{field}"
        );
    }
    assert_eq!(
        cw_http::parse_context(&["\"a\"", "\"b\""], limits()).unwrap(),
        vec!["a", "b"]
    );
    for field in [
        "satisfied, satisfied",
        "satisfied;a",
        "\"satisfied\"",
        "unsatisfied",
    ] {
        let r = Response::builder()
            .header(cw_http::RESULT, field)
            .body(())
            .unwrap();
        assert_eq!(
            cw_http::accept_confirmation(&r, true),
            Err(Error::Unconfirmed)
        );
    }
    let r = Response::builder()
        .header(cw_http::RESULT, "satisfied")
        .header(cw_http::RESULT, "satisfied")
        .body(())
        .unwrap();
    assert!(cw_http::accept_confirmation(&r, true).is_err());
    let r = Response::builder()
        .header(cw_http::RESULT, "satisfied")
        .body(())
        .unwrap();
    assert!(cw_http::accept_confirmation(&r, false).is_err());
    let r = Response::builder()
        .header(cw_http::RESULT, "satisfied")
        .header("connection", "Causal-Result")
        .body(())
        .unwrap();
    assert!(cw_http::accept_confirmation(&r, true).is_err());
}

#[test]
fn server_reports_all_six_outcomes_without_returning_the_application_body() {
    let key = SigningKey::generate();
    let verifier = verifier(*key.verifying_key());
    let mut c_unknown = claims("1");
    c_unknown[CLAIM]["domain"] = json!(OTHER_DOMAIN);
    let mut c_unsupported = claims("opaque");
    c_unsupported[CLAIM]["profile"] = json!("urn:test:unknown");
    let mut c_expired = claims("5");
    c_expired["exp"] = json!(100);
    let tokens = [
        claims("5"),
        claims("6"),
        c_unknown,
        c_unsupported,
        c_expired,
        claims("7"),
    ]
    .iter()
    .map(|c| sign(&key, c))
    .collect::<Vec<_>>();
    let mut request = Request::new(());
    *request.headers_mut() = cw_http::request_headers(&tokens, limits()).unwrap();
    let lineage = BTreeMap::from([
        (
            (ISSUER.into(), DOMAIN.into()),
            Mapping::Relevant {
                component_frontiers: vec![Frontier::At(5)],
                first_terminal_failure: Some(7),
                progress_possible: true,
            },
        ),
        (
            (ISSUER.into(), OTHER_DOMAIN.into()),
            Mapping::Relevant {
                component_frontiers: vec![Frontier::Unknown],
                first_terminal_failure: None,
                progress_possible: true,
            },
        ),
    ]);
    let response = cw_http::observe(
        &request,
        TARGET,
        true,
        &verifier,
        SUBJECT,
        || true,
        || 100,
        || {
            Snapshot::new(
                TARGET.into(),
                Response::new(b"must not escape".to_vec()),
                "v1".into(),
                "v1".into(),
                lineage,
            )
            .map_err(|_| ())
        },
    );
    assert_eq!(response.status(), 503);
    assert_eq!(response.headers()[cw_http::RESULT], "unsatisfied");
    let body: serde_json::Value = serde_json::from_slice(response.body()).unwrap();
    let outcomes = body["outcomes"].as_array().unwrap();
    assert_eq!(
        outcomes
            .iter()
            .map(|v| v["outcome"].clone())
            .collect::<Vec<_>>(),
        [
            "satisfied",
            "unsatisfied",
            "unknown",
            "unsupported",
            "expired",
            "failed"
        ]
        .map(|s| json!(s))
    );
    for (index, value) in outcomes.iter().enumerate() {
        assert_eq!(value["index"], index);
    }
    assert!(!String::from_utf8_lossy(response.body()).contains("must not escape"));
}

#[test]
fn response_status_target_and_vary_cannot_weaken_confirmation() {
    let key = SigningKey::generate();
    let verifier = verifier(*key.verifying_key());
    let req = request(&sign(&key, &claims("5")));
    for status in [202, 304] {
        let response = cw_http::observe(
            &req,
            TARGET,
            true,
            &verifier,
            SUBJECT,
            || true,
            || 100,
            || {
                Ok(snapshot(
                    Response::builder().status(status).body(vec![]).unwrap(),
                    vec![Frontier::At(5)],
                ))
            },
        );
        assert_eq!(response.status(), 500);
        assert!(!response.headers().contains_key(cw_http::RESULT));
    }
    for status in [200, 404, 410] {
        let response = cw_http::observe(
            &req,
            TARGET,
            true,
            &verifier,
            SUBJECT,
            || true,
            || 100,
            || {
                Ok(snapshot(
                    Response::builder()
                        .status(status)
                        .header("vary", "*")
                        .body(vec![])
                        .unwrap(),
                    vec![Frontier::At(5)],
                ))
            },
        );
        assert_eq!(response.status(), status);
        assert_eq!(response.headers()["vary"], "*");
        assert_eq!(response.headers().get_all("vary").iter().count(), 1);
        cw_http::accept_confirmation(&response, true).unwrap();
    }
    let response = cw_http::observe(
        &req,
        "/different-target",
        true,
        &verifier,
        SUBJECT,
        || true,
        || 100,
        || Ok(snapshot(Response::new(vec![]), vec![Frontier::At(5)])),
    );
    assert_eq!(response.status(), 503);
    assert!(!response.headers().contains_key(cw_http::RESULT));
}
