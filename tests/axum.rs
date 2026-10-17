#![cfg(feature = "axum-0_8")]

mod common;

use std::{cell::Cell, convert::Infallible, rc::Rc};

use axum::{body::Body, extract::Request};
use causalweb::{
    axum as causal_axum,
    evidence::SigningKey,
    http::{self as causal_http, RESULT},
    prefix::Frontier,
};
use futures::executor::block_on;
use http::{HeaderValue, Response};
use p256::elliptic_curve::Generate;

use common::*;

fn request() -> Request {
    Request::new(Body::empty())
}

fn fixed_cut() -> causalweb::prefix::Snapshot<Response<Vec<u8>>> {
    snapshot(Response::new(b"covered".to_vec()), vec![Frontier::At(5)])
}

#[test]
fn ordinary_requests_remain_route_owned() {
    let key = SigningKey::generate();
    let verifier = verifier(*key.verifying_key());
    let request = request();
    let authorizations = Rc::new(Cell::new(0));
    let reads = Rc::new(Cell::new(0));
    let authorization_counter = Rc::clone(&authorizations);
    let read_counter = Rc::clone(&reads);

    let outcome = block_on(causal_axum::observe(
        &request,
        causal_axum::ObservationOptions {
            target: TARGET,
            designated_observation: true,
            verifier: &verifier,
            authenticated_subject: SUBJECT,
        },
        move || {
            authorization_counter.set(authorization_counter.get() + 1);
            async { Ok::<bool, Infallible>(true) }
        },
        || 100,
        move || {
            read_counter.set(read_counter.get() + 1);
            async { Ok::<_, Infallible>(fixed_cut()) }
        },
    ))
    .unwrap();

    assert!(outcome.is_none());
    assert_eq!(authorizations.get(), 0);
    assert_eq!(reads.get(), 0);
    assert!(request.headers().is_empty());
}

#[test]
fn constrained_requests_await_the_core_and_convert_the_confirmed_response() {
    let key = SigningKey::generate();
    let verifier = verifier(*key.verifying_key());
    let token = sign(&key, &claims("5"));
    let mut request = request();
    *request.headers_mut() = causal_http::request_headers(&[token], limits()).unwrap();
    let authorizations = Rc::new(Cell::new(0));
    let reads = Rc::new(Cell::new(0));
    let authorization_counter = Rc::clone(&authorizations);
    let read_counter = Rc::clone(&reads);

    let response = block_on(causal_axum::observe(
        &request,
        causal_axum::ObservationOptions {
            target: TARGET,
            designated_observation: true,
            verifier: &verifier,
            authenticated_subject: SUBJECT,
        },
        move || {
            authorization_counter.set(authorization_counter.get() + 1);
            async { Ok::<bool, Infallible>(true) }
        },
        || 100,
        move || {
            read_counter.set(read_counter.get() + 1);
            async { Ok::<_, Infallible>(fixed_cut()) }
        },
    ))
    .unwrap()
    .expect("constrained request must be owned by the adapter");

    assert_eq!(authorizations.get(), 2);
    assert_eq!(reads.get(), 1);
    assert_eq!(response.status(), 200);
    assert_eq!(
        response.headers().get(RESULT),
        Some(&HeaderValue::from_static("satisfied"))
    );
    assert!(response.headers().get(causal_http::CONTEXT).is_none());
}
