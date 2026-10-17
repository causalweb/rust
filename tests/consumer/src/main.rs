use causalweb::{
    evidence::{CommittedEvidence, Issuer, IssuerTrust, Limits, SigningKey, Verifier},
    http as cw_http,
    prefix::{Frontier, Mapping, Snapshot},
};
use http::{Request, Response};
use p256::elliptic_curve::Generate;
use std::collections::{BTreeMap, BTreeSet};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Synthetic SDK exercise, not a storage commitment or recovery demonstration.
    let source = "https://source.example";
    let domain = "https://source.example/domains/orders/epoch-1";
    let subject = "tenant-42";
    let audience = "orders-view";
    let target = "/orders/42";
    let limits = Limits::default();
    let key = SigningKey::generate();
    let verifier = Verifier::new(
        audience.into(),
        vec![IssuerTrust {
            issuer: source.into(),
            keys: BTreeMap::from([("local-test-key".into(), *key.verifying_key())]),
            domains: BTreeSet::from([domain.into()]),
            max_lifetime_seconds: 300,
            clock_skew_seconds: 0,
        }],
        limits,
    )?;
    let issuer = Issuer::new(
        source.into(),
        "local-test-key".into(),
        key,
        BTreeSet::from([domain.into()]),
        300,
        limits,
    )?;
    let evidence = issuer.issue_committed(
        &CommittedEvidence {
            subject,
            audiences: &[audience],
            domain,
            position: 5,
            issued_at: 100,
            expires_at: 200,
            evidence_id: "urn:uuid:f004c937-c766-4119-964b-32ff598be9f4",
        },
        100,
    )?;
    let mut request = Request::new(());
    *request.headers_mut() = cw_http::request_headers(&[evidence], limits)?;
    let read_at = |frontier| {
        Snapshot::new(
            target.into(),
            Response::new(br#"{"order":42}"#.to_vec()),
            "orders-projection/v1".into(),
            "orders-schema/v1".into(),
            BTreeMap::from([(
                (source.into(), domain.into()),
                Mapping::Relevant {
                    component_frontiers: vec![Frontier::At(frontier)],
                    first_terminal_failure: None,
                    progress_possible: true,
                },
            )]),
        )
        .map_err(|_| ())
    };
    let stale = cw_http::observe(
        &request,
        target,
        true,
        &verifier,
        subject,
        || true,
        || 100,
        || read_at(4),
    );
    assert_eq!(stale.status(), 412);
    assert!(cw_http::accept_confirmation(&stale, true).is_err());
    let fresh = cw_http::observe(
        &request,
        target,
        true,
        &verifier,
        subject,
        || true,
        || 100,
        || read_at(5),
    );
    cw_http::accept_confirmation(&fresh, true)?;
    assert_eq!(fresh.body(), br#"{"order":42}"#);
    let denied = cw_http::observe(
        &request,
        target,
        true,
        &verifier,
        subject,
        || false,
        || 100,
        || panic!("must not select state"),
    );
    assert_eq!(denied.status(), 403);
    assert!(!denied.headers().contains_key(cw_http::RESULT));
    println!(
        "Packaged-crate consumer: stale rejection, confirmed observation, and access denial passed"
    );
    Ok(())
}
