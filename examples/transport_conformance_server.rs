//! Test-only raw HTTP/1.1 server for the `http-transport-server-v1` profile.
//!
//! It is deliberately limited to loopback requests without request bodies. It is
//! not a reusable HTTP server, storage adapter, or deployment component.

use std::{
    collections::{BTreeMap, BTreeSet},
    convert::Infallible,
    error::Error,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use causalweb::{
    CLAIM, PROFILE,
    evidence::{IssuerTrust, Limits, SigningKey, Verifier},
    http::{CONTEXT, ObservationOptions, REQUIRE, observe},
    prefix::{Frontier, Mapping, Snapshot},
};
use http::{HeaderName, HeaderValue, Method, Request, Response, StatusCode, header};
use p256::ecdsa::{Signature, signature::Signer};
use p256::elliptic_curve::Generate;
use serde_json::json;

const ISSUER: &str = "https://issuer.example";
const AUDIENCE: &str = "https://verifier.example/causal";
const SUBJECT: &str = "opaque-tenant";
const DOMAIN: &str = "https://issuer.example/domains/orders/2026";
const TARGET: &str = "/orders/123";

fn signed_evidence(key: &SigningKey, id: &str, index: usize) -> String {
    let header = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(
            &json!({"alg":"ES256","kid":"transport-conformance","typ":"cw-evidence+jwt"}),
        )
        .expect("static header serializes"),
    );
    let payload = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&json!({
            "iss": ISSUER,
            "sub": SUBJECT,
            "aud": AUDIENCE,
            "iat": 1,
            "exp": 1000,
            "jti": format!("urn:transport-conformance:{id}:{index}"),
            CLAIM: {
                "v": 1,
                "profile": PROFILE,
                "domain": DOMAIN,
                "position": "5",
                "commit": "stable"
            }
        }))
        .expect("static claims serialize"),
    );
    let input = format!("{header}.{payload}");
    let signature: Signature = key.sign(input.as_bytes());
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()))
}

fn fixture(key: &SigningKey, id: &str) -> Vec<String> {
    if id == "TRN-001" {
        vec![signed_evidence(key, id, 0), signed_evidence(key, id, 1)]
    } else {
        vec![signed_evidence(key, id, 0)]
    }
}

fn read_request(stream: &mut TcpStream) -> Result<Request<()>, Box<dyn Error>> {
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes)?;
    let text = std::str::from_utf8(&bytes)?;
    let (head, _) = text
        .split_once("\r\n\r\n")
        .ok_or("request lacks a header terminator")?;
    let mut lines = head.split("\r\n");
    let start = lines.next().ok_or("request lacks a request line")?;
    let mut pieces = start.split_whitespace();
    let method = pieces
        .next()
        .ok_or("request lacks a method")?
        .parse::<Method>()?;
    let path = pieces.next().ok_or("request lacks a path")?;
    if pieces.next() != Some("HTTP/1.1") || pieces.next().is_some() {
        return Err("request does not use HTTP/1.1".into());
    }
    let mut request = Request::builder().method(method).uri(path).body(())?;
    for line in lines {
        let (name, value) = line.split_once(':').ok_or("invalid request field")?;
        request.headers_mut().append(
            HeaderName::from_bytes(name.trim().as_bytes())?,
            HeaderValue::from_str(value.trim())?,
        );
    }
    Ok(request)
}

fn write_response(
    stream: &mut TcpStream,
    method: &Method,
    mut response: Response<Vec<u8>>,
) -> Result<(), Box<dyn Error>> {
    let body = if *method == Method::HEAD {
        Vec::new()
    } else {
        std::mem::take(response.body_mut())
    };
    response.headers_mut().insert(
        header::CONTENT_LENGTH,
        HeaderValue::from_str(&body.len().to_string())?,
    );
    response
        .headers_mut()
        .insert(header::CONNECTION, HeaderValue::from_static("close"));
    write!(
        stream,
        "HTTP/1.1 {} {}\r\n",
        response.status().as_u16(),
        response.status().canonical_reason().unwrap_or("")
    )?;
    for (name, value) in response.headers() {
        write!(stream, "{}: {}\r\n", name.as_str(), value.to_str()?)?;
    }
    stream.write_all(b"\r\n")?;
    stream.write_all(&body)?;
    Ok(())
}

fn fixture_response(key: &SigningKey, id: &str) -> Response<Vec<u8>> {
    let body = serde_json::to_vec(&json!({"requirements": fixture(key, id)}))
        .expect("fixture response serializes");
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .body(body)
        .expect("static fixture response is valid")
}

fn selected(path: &str) -> (u64, StatusCode, &'static str, bool) {
    match path {
        "/observe/TRN-001" => (4, StatusCode::OK, "stale", false),
        "/observe/TRN-002" => (5, StatusCode::OK, "covered", true),
        _ => (5, StatusCode::ACCEPTED, "pending", false),
    }
}

fn observe_request(request: &Request<()>, verifier: &Verifier) -> Response<Vec<u8>> {
    if request.uri().path() == "/ordinary" && !request.headers().contains_key(REQUIRE) {
        let mut response = Response::new(Vec::new());
        *response.status_mut() = StatusCode::NO_CONTENT;
        response.headers_mut().insert(
            "x-causalweb-conformance-read-calls",
            HeaderValue::from_static("0"),
        );
        return response;
    }
    let (frontier, status, body, context) = selected(request.uri().path());
    let mut read_calls = 0usize;
    let response = observe(
        ObservationOptions {
            request,
            target: TARGET,
            designated_observation: true,
            verifier,
            authenticated_subject: SUBJECT,
        },
        || Ok::<bool, Infallible>(true),
        || 100,
        || {
            read_calls += 1;
            let mut representation = Response::builder()
                .status(status)
                .body(body.as_bytes().to_vec())
                .expect("static representation response is valid");
            if context {
                representation
                    .headers_mut()
                    .insert(CONTEXT, HeaderValue::from_static("not-evidence"));
            }
            Ok::<_, Infallible>(
                Snapshot::new(
                    TARGET.into(),
                    representation,
                    "contract/v1".into(),
                    "schema/v1".into(),
                    BTreeMap::from([(
                        (ISSUER.into(), DOMAIN.into()),
                        Mapping::Relevant {
                            component_frontiers: vec![Frontier::At(frontier)],
                            first_terminal_failure: None,
                            progress_possible: true,
                        },
                    )]),
                )
                .expect("static snapshot is valid"),
            )
        },
    )
    .unwrap_or_else(|error| error.into_response());
    let mut response = response;
    response.headers_mut().insert(
        "x-causalweb-conformance-read-calls",
        HeaderValue::from_str(&read_calls.to_string()).expect("read count is a header value"),
    );
    response
}

fn main() -> Result<(), Box<dyn Error>> {
    let signing_key = SigningKey::generate();
    let verifier = Verifier::new(
        AUDIENCE.into(),
        vec![IssuerTrust {
            issuer: ISSUER.into(),
            keys: BTreeMap::from([("transport-conformance".into(), *signing_key.verifying_key())]),
            domains: BTreeSet::from([DOMAIN.into()]),
            max_lifetime_seconds: 86_400,
            clock_skew_seconds: 0,
        }],
        Limits::default(),
    )?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    println!(
        "{}",
        json!({
            "format":"causal-web-conformance-transport-server-v1",
            "origin":format!("http://127.0.0.1:{port}")
        })
    );
    std::io::stdout().flush()?;
    for stream in listener.incoming() {
        let mut stream = stream?;
        let request = read_request(&mut stream)?;
        let response = if let Some(id) = request.uri().path().strip_prefix("/fixture/") {
            fixture_response(&signing_key, id)
        } else {
            observe_request(&request, &verifier)
        };
        write_response(&mut stream, request.method(), response)?;
    }
    Ok(())
}
