//! Route-scoped Axum 0.8 observation adapter.
//!
//! This module converts an Axum request's initial HTTP fields into the core binding and awaits
//! application-owned authorization and fixed-cut reads. It does not own routing, authentication,
//! storage transactions, CORS, TLS, cancellation, or source issuance.

use std::future::Future;

use axum::{body::Body, extract::Request, response::Response};

use crate::{
    evidence::Verifier,
    http::{
        ObservationError, ObservationOptions as CoreObservationOptions, REQUIRE,
        observe_async as core_observe,
    },
    prefix::Snapshot,
};

/// Route-owned Causal Web inputs. The route supplies an already authenticated subject and the
/// authorization/read closures; this adapter never derives either value from causal evidence.
#[derive(Clone, Copy)]
pub struct ObservationOptions<'a> {
    pub target: &'a str,
    pub designated_observation: bool,
    pub verifier: &'a Verifier,
    pub authenticated_subject: &'a str,
}

/// Returns whether the initial request fields ask for a constrained observation.
/// A route can keep ordinary requests on its normal response path.
pub fn has_causal_requirement(request: &Request) -> bool {
    request.headers().contains_key(REQUIRE)
}

/// Evaluate one finite, designated Axum observation without blocking asynchronous storage I/O.
///
/// The request is consumed because this adapter owns a causal response path. It returns `None`
/// for an ordinary request so the route can retain its normal response behavior. Call it only from
/// a route whose request body and trailers are not separately interpreted as causal input. A
/// returned [`ObservationError`] is local adapter state: redact it and convert it with
/// [`ObservationError::into_response`] before returning it to an external client.
pub async fn observe<A, AFut, C, R, RFut, AE, RE>(
    request: Request,
    options: ObservationOptions<'_>,
    authorize: A,
    clock: C,
    read: R,
) -> Result<Option<Response>, ObservationError<AE, RE>>
where
    A: FnMut() -> AFut,
    AFut: Future<Output = Result<bool, AE>>,
    C: FnMut() -> u64,
    R: FnOnce() -> RFut,
    RFut: Future<Output = Result<Snapshot<::http::Response<Vec<u8>>>, RE>>,
{
    if !has_causal_requirement(&request) {
        return Ok(None);
    }
    let request = request.map(|_| ());
    let response = core_observe(
        CoreObservationOptions {
            request: &request,
            target: options.target,
            designated_observation: options.designated_observation,
            verifier: options.verifier,
            authenticated_subject: options.authenticated_subject,
        },
        authorize,
        clock,
        read,
    )
    .await?;
    Ok(Some(response.map(Body::from)))
}
