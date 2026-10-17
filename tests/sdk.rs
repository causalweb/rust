mod common;

use causalweb::{
    Error,
    evidence::{MAX_DATE, SigningKey},
};
use causalweb::{http as cw_http, prefix::Frontier};
use common::*;
use http::{Request, Response};
use p256::elliptic_curve::Generate;
use std::{cell::Cell, convert::Infallible, error::Error as _, io};

fn options<'a>(
    request: &'a Request<()>,
    verifier: &'a causalweb::evidence::Verifier,
) -> cw_http::ObservationOptions<'a> {
    cw_http::ObservationOptions {
        request,
        target: TARGET,
        designated_observation: true,
        verifier,
        authenticated_subject: SUBJECT,
    }
}

fn request(token: String) -> Request<()> {
    let mut request = Request::new(());
    *request.headers_mut() = cw_http::request_headers(&[token], limits()).unwrap();
    request
}

fn assert_safe(response: Response<Vec<u8>>, status: u16) {
    assert_eq!(response.status(), status);
    assert!(response.body().is_empty());
    assert!(!response.headers().contains_key(cw_http::RESULT));
    assert!(!response.headers().contains_key(cw_http::CONTEXT));
    assert_eq!(response.headers()["cache-control"], "no-store");
}

#[test]
fn typed_issuance_round_trips_the_entire_prefix_range() {
    let key = SigningKey::generate();
    let verifier = verifier(*key.verifying_key());
    let issuer = issuer(key);
    for position in [0, 1, 9_007_199_254_740_992, u64::MAX] {
        let token = issuer.issue_committed(&committed(position), 100).unwrap();
        let evidence = verifier.verify(&token, SUBJECT, 100).unwrap();
        assert_eq!(evidence.position(), position.to_string());
        assert_eq!(evidence.domain(), DOMAIN);
        assert_eq!(evidence.expires_at(), 1000);
    }
}

#[test]
fn typed_issuance_still_validates_semantic_constraints() {
    let issuer = issuer(SigningKey::generate());
    for fact in [
        causalweb::evidence::CommittedEvidence {
            subject: "",
            ..committed(5)
        },
        causalweb::evidence::CommittedEvidence {
            audiences: &[],
            ..committed(5)
        },
        causalweb::evidence::CommittedEvidence {
            audiences: &[AUDIENCE, AUDIENCE],
            ..committed(5)
        },
        causalweb::evidence::CommittedEvidence {
            domain: OTHER_DOMAIN,
            ..committed(5)
        },
        causalweb::evidence::CommittedEvidence {
            issued_at: 101,
            ..committed(5)
        },
        causalweb::evidence::CommittedEvidence {
            expires_at: 100,
            ..committed(5)
        },
        causalweb::evidence::CommittedEvidence {
            expires_at: MAX_DATE + 1,
            ..committed(5)
        },
        causalweb::evidence::CommittedEvidence {
            evidence_id: "",
            ..committed(5)
        },
    ] {
        assert_eq!(
            issuer.issue_committed(&fact, 100),
            Err(Error::InvalidEvidence)
        );
    }
}

#[test]
fn authorization_failures_retain_the_cause_and_checkpoint_without_reading_or_leaking() {
    let key = SigningKey::generate();
    let verifier = verifier(*key.verifying_key());
    let request = request(sign(&key, &claims("5")));
    for fail_at in [1, 2] {
        let checks = Cell::new(0);
        let reads = Cell::new(0);
        let error = cw_http::observe(
            options(&request, &verifier),
            || {
                checks.set(checks.get() + 1);
                if checks.get() == fail_at {
                    Err(io::Error::other("private auth credential"))
                } else {
                    Ok(true)
                }
            },
            || 100,
            || -> Result<_, Infallible> {
                reads.set(reads.get() + 1);
                Ok(snapshot(
                    Response::new(b"private application data".to_vec()),
                    vec![Frontier::At(5)],
                ))
            },
        )
        .unwrap_err();
        assert_eq!(error.code(), "authorization-unavailable");
        assert_eq!(
            error.source().unwrap().to_string(),
            "private auth credential"
        );
        assert!(!format!("{error:?} {error}").contains("private"));
        match &error {
            cw_http::ObservationError::Authorization { check, source } => {
                assert_eq!(
                    *check,
                    if fail_at == 1 {
                        cw_http::AuthorizationCheck::BeforeRead
                    } else {
                        cw_http::AuthorizationCheck::BeforeResponse
                    }
                );
                assert_eq!(source.kind(), io::ErrorKind::Other);
            }
            _ => panic!("wrong local failure category"),
        }
        assert_eq!(reads.get(), if fail_at == 1 { 0 } else { 1 });
        assert_safe(error.into_response(), 503);
    }
}

#[test]
fn read_errors_are_not_erased_or_reclassified_as_causal_outcomes() {
    let key = SigningKey::generate();
    let verifier = verifier(*key.verifying_key());
    let request = request(sign(&key, &claims("5")));
    let error = cw_http::observe(
        options(&request, &verifier),
        || Ok::<_, Infallible>(true),
        || 100,
        || {
            Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "private database connection",
            ))
        },
    )
    .unwrap_err();
    assert_eq!(error.code(), "read-unavailable");
    assert_eq!(
        error.source().unwrap().to_string(),
        "private database connection"
    );
    assert!(!format!("{error:?} {error}").contains("private"));
    assert!(
        matches!(&error, cw_http::ObservationError::Read(source) if source.kind() == io::ErrorKind::ConnectionReset)
    );
    assert_safe(error.into_response(), 503);
}

#[test]
fn contract_failures_remain_local_and_convert_to_safe_responses() {
    let key = SigningKey::generate();
    let verifier = verifier(*key.verifying_key());
    let request = request(sign(&key, &claims("5")));
    let mut wrong_target = options(&request, &verifier);
    wrong_target.target = "/different";
    let read = || Ok::<_, Infallible>(snapshot(Response::new(vec![]), vec![Frontier::At(5)]));
    let error =
        cw_http::observe(wrong_target, || Ok::<_, Infallible>(true), || 100, read).unwrap_err();
    assert!(matches!(
        error,
        cw_http::ObservationError::SnapshotTargetMismatch
    ));
    assert_safe(error.into_response(), 503);
    let error = cw_http::observe(
        options(&request, &verifier),
        || Ok::<_, Infallible>(true),
        || 100,
        || {
            Ok::<_, Infallible>(snapshot(
                Response::builder()
                    .status(202)
                    .body(b"private application data".to_vec())
                    .unwrap(),
                vec![Frontier::At(5)],
            ))
        },
    )
    .unwrap_err();
    assert!(matches!(
        error,
        cw_http::ObservationError::InvalidRepresentation
    ));
    assert_safe(error.into_response(), 500);
}

#[test]
fn denied_invalid_and_unsatisfied_responses_are_not_local_failures() {
    let key = SigningKey::generate();
    let verifier = verifier(*key.verifying_key());
    let request = request(sign(&key, &claims("5")));
    let denied = cw_http::observe(
        options(&request, &verifier),
        || Ok::<_, Infallible>(false),
        || 100,
        || -> Result<_, Infallible> { panic!("must not read") },
    )
    .unwrap();
    assert_safe(denied, 403);
    let invalid = Request::new(());
    let invalid = cw_http::observe(
        options(&invalid, &verifier),
        || Ok::<_, Infallible>(true),
        || 100,
        || -> Result<_, Infallible> { panic!("must not read") },
    )
    .unwrap();
    assert_eq!(invalid.status(), 400);
    let unsatisfied = cw_http::observe(
        options(&request, &verifier),
        || Ok::<_, Infallible>(true),
        || 100,
        || {
            Ok::<_, Infallible>(snapshot(
                Response::new(b"stale".to_vec()),
                vec![Frontier::At(4)],
            ))
        },
    )
    .unwrap();
    assert_eq!(unsatisfied.status(), 412);
    assert_eq!(unsatisfied.headers()[cw_http::RESULT], "unsatisfied");
}
