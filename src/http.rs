//! HTTP binding helpers with no network stack or automatic redirects.
use ::http::{HeaderMap, HeaderValue, Method, Request, Response, StatusCode, header};
use serde_json::json;
use sfv::{BareItem, Item, List, ListEntry, ListSerializer, Parser, StringRef};
use std::fmt;

use crate::{
    Error, PROFILE,
    evidence::{Limits, Verifier},
    prefix::{self, Outcome, Snapshot},
};

pub const REQUIRE: &str = "causal-require";
pub const CONTEXT: &str = "causal-context";
pub const RESULT: &str = "causal-result";

/// Parse combined field lines without deduplication or changing evidence bytes.
pub fn parse_context(lines: &[&str], limits: Limits) -> Result<Vec<String>, Error> {
    limits.validate()?;
    let bytes = lines
        .iter()
        .try_fold(0usize, |sum, value| sum.checked_add(value.len()))
        .and_then(|sum| sum.checked_add(lines.len().saturating_sub(1).saturating_mul(2)))
        .ok_or(Error::TooLarge)?;
    if bytes > limits.max_header_bytes {
        return Err(Error::TooLarge);
    }
    let combined = lines.join(", ");
    let list: List = Parser::new(&combined)
        .parse()
        .map_err(|_| Error::InvalidRequirements)?;
    if list.len() > limits.max_requirements {
        return Err(Error::TooLarge);
    }
    if list.is_empty() {
        return Err(Error::InvalidRequirements);
    }
    list.into_iter()
        .map(|entry| match entry {
            ListEntry::Item(Item {
                bare_item: BareItem::String(value),
                params,
            }) if params.is_empty() => {
                if value.as_str().len() > limits.max_token_bytes {
                    return Err(Error::TooLarge);
                }
                Ok(value.as_str().to_owned())
            }
            _ => Err(Error::InvalidRequirements),
        })
        .collect()
}

pub fn serialize_context(tokens: &[String], limits: Limits) -> Result<String, Error> {
    limits.validate()?;
    if tokens.len() > limits.max_requirements {
        return Err(Error::TooLarge);
    }
    if tokens.is_empty() {
        return Err(Error::InvalidRequirements);
    }
    let mut serializer = ListSerializer::new();
    for token in tokens {
        if token.len() > limits.max_token_bytes {
            return Err(Error::TooLarge);
        }
        serializer.bare_item(StringRef::from_str(token).map_err(|_| Error::InvalidRequirements)?);
    }
    let field = serializer.finish().ok_or(Error::InvalidRequirements)?;
    if field.len() > limits.max_header_bytes {
        return Err(Error::TooLarge);
    }
    Ok(field)
}

pub fn request_headers(tokens: &[String], limits: Limits) -> Result<HeaderMap, Error> {
    let mut headers = HeaderMap::new();
    headers.insert(
        REQUIRE,
        HeaderValue::from_str(&serialize_context(tokens, limits)?)
            .map_err(|_| Error::InvalidRequirements)?,
    );
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-cache, no-store"),
    );
    Ok(headers)
}

pub fn allowed_confirmation_status(status: u16) -> bool {
    ((200..=299).contains(&status) && status != 202) || status == 404 || status == 410
}

fn connection_nominates_causal(headers: &HeaderMap) -> bool {
    headers.get_all(header::CONNECTION).iter().any(|line| {
        line.to_str().map_or(true, |s| {
            s.split(',').any(|part| {
                [REQUIRE, CONTEXT, RESULT]
                    .iter()
                    .any(|name| part.trim().eq_ignore_ascii_case(name))
            })
        })
    })
}

/// Check before exposing a response body. `authenticated` includes TLS and ordinary application checks.
pub fn accept_confirmation<T>(response: &Response<T>, authenticated: bool) -> Result<(), Error> {
    if !authenticated
        || !allowed_confirmation_status(response.status().as_u16())
        || connection_nominates_causal(response.headers())
    {
        return Err(Error::Unconfirmed);
    }
    let values: Vec<_> = response.headers().get_all(RESULT).iter().collect();
    if values.len() != 1 {
        return Err(Error::Unconfirmed);
    }
    let item: Item = Parser::new(values[0].to_str().map_err(|_| Error::Unconfirmed)?)
        .parse()
        .map_err(|_| Error::Unconfirmed)?;
    match item.bare_item {
        BareItem::Token(token) if token.as_str() == "satisfied" && item.params.is_empty() => Ok(()),
        _ => Err(Error::Unconfirmed),
    }
}

fn problem(
    status: StatusCode,
    kind: &str,
    title: &str,
    outcomes: Option<Vec<serde_json::Value>>,
) -> Response<Vec<u8>> {
    let mut body = json!({"type":format!("https://github.com/causalweb/spec/problems/{kind}"), "title":title, "status":status.as_u16()});
    if let Some(outcomes) = outcomes {
        body["outcomes"] = json!(outcomes);
    }
    let mut response = Response::new(serde_json::to_vec(&body).expect("serializable problem"));
    *response.status_mut() = status;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/problem+json"),
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn protocol_error(error: Error) -> Response<Vec<u8>> {
    match error {
        Error::TooLarge => problem(
            StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
            "request-too-large",
            "Causal request exceeds configured limits",
            None,
        ),
        Error::NotObservation => problem(
            StatusCode::BAD_REQUEST,
            "not-observation",
            "Endpoint is not a supported observation",
            None,
        ),
        _ => problem(
            StatusCode::BAD_REQUEST,
            "invalid-requirements",
            "Invalid causal requirements",
            None,
        ),
    }
}

fn ordinary_error(status: StatusCode) -> Response<Vec<u8>> {
    let mut response = Response::new(Vec::new());
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// Application-supplied context for one designated observation exchange.
/// Neither this value nor causal evidence authenticates the subject or authorizes
/// the target. Those remain obligations of the application and `authorize` callback.
#[derive(Clone, Copy)]
pub struct ObservationOptions<'a> {
    pub request: &'a Request<()>,
    pub target: &'a str,
    pub designated_observation: bool,
    pub verifier: &'a Verifier,
    pub authenticated_subject: &'a str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorizationCheck {
    BeforeRead,
    BeforeResponse,
}

/// A local adapter/contract failure, not a causal dependency outcome.
///
/// Causes retain their original types for application diagnostics. They can contain
/// credentials or other private data: redact before logging, and never serialize
/// them into an HTTP response. Debug/Display deliberately omit underlying causes.
pub enum ObservationError<A, R> {
    Authorization {
        check: AuthorizationCheck,
        source: A,
    },
    Read(R),
    SnapshotTargetMismatch,
    InvalidRepresentation,
}

impl<A, R> ObservationError<A, R> {
    /// Machine-readable local category; not a protocol field or dependency outcome.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Authorization { .. } => "authorization-unavailable",
            Self::Read(_) => "read-unavailable",
            Self::SnapshotTargetMismatch => "snapshot-target-mismatch",
            Self::InvalidRepresentation => "invalid-representation",
        }
    }

    /// Discard local diagnostics and construct an ordinary, empty, no-store error.
    /// No causal marker, application body, evidence, or cause is returned.
    pub fn into_response(self) -> Response<Vec<u8>> {
        ordinary_error(match self {
            Self::InvalidRepresentation => StatusCode::INTERNAL_SERVER_ERROR,
            _ => StatusCode::SERVICE_UNAVAILABLE,
        })
    }
}

impl<A, R> fmt::Display for ObservationError<A, R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Causal Web observer: {}", self.code())
    }
}

impl<A, R> fmt::Debug for ObservationError<A, R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl<A: std::error::Error + 'static, R: std::error::Error + 'static> std::error::Error
    for ObservationError<A, R>
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Authorization { source, .. } => Some(source),
            Self::Read(source) => Some(source),
            _ => None,
        }
    }
}

/// Single-attempt observer. No progress waiting is performed; `Prefer: wait` is ignored.
///
/// Authorization is checked before evidence processing and again before responding.
/// The reader must return an immutable representation/lineage tuple for `target`.
/// Transport adapters own TLS, CSRF, initial-field/trailer separation, cancellation,
/// ordinary preconditions, header limits below this layer, and snapshot durability.
///
/// `Ok` contains an HTTP response, including denied access, invalid requirements,
/// and indexed causal failures. `Err` preserves a local adapter/contract failure.
/// Inspect/redact the error locally, then use [`ObservationError::into_response`].
/// Callback panics are not caught. Bound callback work and cancellation in the host.
pub fn observe<A, C, R, AE, RE>(
    options: ObservationOptions<'_>,
    mut authorize: A,
    mut clock: C,
    read: R,
) -> Result<Response<Vec<u8>>, ObservationError<AE, RE>>
where
    A: FnMut() -> Result<bool, AE>,
    C: FnMut() -> u64,
    R: FnOnce() -> Result<Snapshot<Response<Vec<u8>>>, RE>,
{
    let ObservationOptions {
        request,
        target,
        designated_observation,
        verifier,
        authenticated_subject,
    } = options;
    if !authorize().map_err(|source| ObservationError::Authorization {
        check: AuthorizationCheck::BeforeRead,
        source,
    })? {
        return Ok(ordinary_error(StatusCode::FORBIDDEN));
    }
    if connection_nominates_causal(request.headers()) {
        return Ok(protocol_error(Error::InvalidRequirements));
    }
    let lines = request
        .headers()
        .get_all(REQUIRE)
        .iter()
        .map(|value| value.to_str().map_err(|_| Error::InvalidRequirements))
        .collect::<Result<Vec<_>, _>>();
    let tokens = match lines.and_then(|lines| parse_context(&lines, verifier.limits())) {
        Ok(tokens) => tokens,
        Err(error) => return Ok(protocol_error(error)),
    };
    if request.method() == Method::HEAD {
        return Ok(protocol_error(Error::InvalidRequirements));
    }
    if !designated_observation {
        return Ok(protocol_error(Error::NotObservation));
    }
    let now = clock();
    for token in &tokens {
        if let Err(error) = verifier.verify(token, authenticated_subject, now) {
            return Ok(protocol_error(error));
        }
    }
    let snapshot = read().map_err(ObservationError::Read)?;
    if snapshot.target != target {
        return Err(ObservationError::SnapshotTargetMismatch);
    }
    if !authorize().map_err(|source| ObservationError::Authorization {
        check: AuthorizationCheck::BeforeResponse,
        source,
    })? {
        return Ok(ordinary_error(StatusCode::FORBIDDEN));
    }
    let now = clock();
    let mut evaluations = Vec::with_capacity(tokens.len());
    // Re-authenticate with the current exchange policy, then recheck expiry after the read.
    for token in &tokens {
        let evidence = match verifier.verify(token, authenticated_subject, now) {
            Ok(evidence) => evidence,
            Err(error) => return Ok(protocol_error(error)),
        };
        evaluations.push(prefix::evaluate(&evidence, &snapshot, now));
    }
    if evaluations.iter().all(|e| e.outcome == Outcome::Satisfied) {
        let mut response = snapshot.representation;
        if !allowed_confirmation_status(response.status().as_u16())
            || connection_nominates_causal(response.headers())
        {
            return Err(ObservationError::InvalidRepresentation);
        }
        // Context issuance is separate; an adapter must not smuggle unvalidated evidence here.
        response.headers_mut().remove(CONTEXT);
        response
            .headers_mut()
            .insert(RESULT, HeaderValue::from_static("satisfied"));
        response.headers_mut().insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static("private, no-store"),
        );
        let varies_all = response
            .headers()
            .get_all(header::VARY)
            .iter()
            .any(|value| {
                value
                    .to_str()
                    .is_ok_and(|s| s.split(',').any(|v| v.trim() == "*"))
            });
        if varies_all {
            response
                .headers_mut()
                .insert(header::VARY, HeaderValue::from_static("*"));
        } else {
            response
                .headers_mut()
                .append(header::VARY, HeaderValue::from_static("Causal-Require"));
        }
        Ok(response)
    } else {
        let failed = evaluations.iter().any(|e| e.outcome == Outcome::Failed);
        let outcomes = evaluations
            .iter()
            .enumerate()
            .map(|(index, evaluation)| {
                let mut value = serde_json::to_value(evaluation).expect("serializable evaluation");
                value["index"] = json!(index);
                value
            })
            .collect();
        let status = if failed {
            StatusCode::SERVICE_UNAVAILABLE
        } else {
            StatusCode::PRECONDITION_FAILED
        };
        let mut response = problem(
            status,
            "requirements-not-satisfied",
            "Causal requirements were not satisfied",
            Some(outcomes),
        );
        response
            .headers_mut()
            .insert(RESULT, HeaderValue::from_static("unsatisfied"));
        Ok(response)
    }
}

pub fn capabilities(verifier: &Verifier) -> serde_json::Value {
    let limits = verifier.limits();
    json!({"protocol":"0.1", "status":"experimental", "audience":verifier.audience(),
        "profiles":[PROFILE], "evidence_formats":["application/cw-evidence+jwt"], "algorithms":["ES256"],
        "max_requirements":limits.max_requirements, "max_header_bytes":limits.max_header_bytes, "max_wait_seconds":0})
}
