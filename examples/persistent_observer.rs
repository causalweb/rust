//! Local, POSIX-only test observer for cross-runtime recovery experiments.
//!
//! This process verifies TypeScript-issued evidence and stores a projection frontier
//! together with the response representation in one replaced document. Its delivery
//! endpoint is a deliberately unauthenticated loopback test channel: a deployment
//! must authenticate and bind application events independently of Causal Web evidence.

use std::{
    collections::{BTreeMap, BTreeSet},
    convert::Infallible,
    env,
    error::Error,
    fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
};

use ::http::{Request, Response, StatusCode, header};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use causalweb::{
    evidence::{IssuerTrust, Limits, Verifier, VerifyingKey},
    http::{self as protocol_http, ObservationOptions},
    prefix::{Frontier, Mapping, Snapshot, position},
};
use serde::{Deserialize, Serialize};
use serde_json::json;

const ISSUER: &str = "https://typescript-orders.example";
const KID: &str = "typescript-persistent-demo";
const SUBJECT: &str = "tenant-example";
const AUDIENCE: &str = "https://orders-view.example/causal";
const DOMAIN: &str = "https://typescript-orders.example/domains/orders";
const TARGET: &str = "/orders";

#[derive(Debug)]
struct Arguments {
    state: PathBuf,
    now: u64,
    bind: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct Event {
    id: String,
    position: String,
    order: String,
    issued_at: String,
    expires_at: String,
    evidence: String,
}

#[derive(Debug, Default, Deserialize, Serialize)]
struct State {
    frontier: u64,
    orders: Vec<String>,
    applied: Vec<String>,
    pending: Vec<Event>,
}

#[derive(Deserialize)]
struct PublicJwk {
    kty: String,
    crv: String,
    x: String,
    y: String,
}

struct Incoming {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

fn next_value(
    args: &mut impl Iterator<Item = String>,
    name: &str,
) -> Result<String, Box<dyn Error>> {
    args.next()
        .ok_or_else(|| format!("missing value for {name}").into())
}

fn arguments() -> Result<Arguments, Box<dyn Error>> {
    let mut values = env::args().skip(1);
    let mut state = None;
    let mut now = None;
    let mut bind = None;
    while let Some(value) = values.next() {
        match value.as_str() {
            "--state" => state = Some(PathBuf::from(next_value(&mut values, "--state")?)),
            "--now" => now = Some(next_value(&mut values, "--now")?.parse()?),
            "--listen" => bind = Some(next_value(&mut values, "--listen")?),
            _ => return Err(format!("unknown argument {value}").into()),
        }
    }
    Ok(Arguments {
        state: state.ok_or("--state is required")?,
        now: now.ok_or("--now is required")?,
        bind: bind.ok_or("--listen is required")?,
    })
}

fn load(path: &Path) -> Result<State, Box<dyn Error>> {
    match fs::read(path) {
        Ok(bytes) => Ok(serde_json::from_slice(&bytes)?),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(State::default()),
        Err(error) => Err(error.into()),
    }
}

#[cfg(not(unix))]
fn replace(_path: &Path, _state: &State) -> Result<(), Box<dyn Error>> {
    Err("persistent_observer requires POSIX atomic rename semantics".into())
}

#[cfg(unix)]
fn replace(path: &Path, state: &State) -> Result<(), Box<dyn Error>> {
    let parent = path.parent().ok_or("state path has no parent")?;
    fs::create_dir_all(parent)?;
    let temporary = path.with_extension("tmp");
    fs::write(&temporary, serde_json::to_vec(state)?)?;
    fs::rename(temporary, path)?;
    Ok(())
}

fn verifying_key() -> Result<VerifyingKey, Box<dyn Error>> {
    let jwk: PublicJwk = serde_json::from_str(&env::var("CAUSALWEB_DEMO_PUBLIC_JWK")?)?;
    if jwk.kty != "EC" || jwk.crv != "P-256" {
        return Err("test public JWK must be EC P-256".into());
    }
    let x = URL_SAFE_NO_PAD.decode(jwk.x)?;
    let y = URL_SAFE_NO_PAD.decode(jwk.y)?;
    if x.len() != 32 || y.len() != 32 {
        return Err("test public JWK coordinate must be 32 bytes".into());
    }
    let mut bytes = Vec::with_capacity(65);
    bytes.push(4);
    bytes.extend(x);
    bytes.extend(y);
    Ok(VerifyingKey::from_sec1_bytes(&bytes)?)
}

fn verifier() -> Result<Verifier, Box<dyn Error>> {
    Ok(Verifier::new(
        AUDIENCE.into(),
        vec![IssuerTrust {
            issuer: ISSUER.into(),
            keys: [(KID.into(), verifying_key()?)].into_iter().collect(),
            domains: [DOMAIN.into()].into_iter().collect::<BTreeSet<_>>(),
            max_lifetime_seconds: 3600,
            clock_skew_seconds: 0,
        }],
        Limits::default(),
    )?)
}

fn valid_order(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn deliver(
    path: &Path,
    verifier: &Verifier,
    event: Event,
    now: u64,
    crash_after_apply: bool,
) -> Result<(), Box<dyn Error>> {
    if !valid_order(&event.order) || event.id.is_empty() || event.evidence.is_empty() {
        return Err("invalid delivery event".into());
    }
    let evidence = verifier.verify(&event.evidence, SUBJECT, now)?;
    let event_position = position(&event.position)?;
    if evidence.domain() != DOMAIN || position(evidence.position())? != event_position {
        return Err("delivery does not match verified evidence".into());
    }
    let mut state = load(path)?;
    if event_position <= state.frontier {
        if state.applied.contains(&event.evidence) {
            return Ok(());
        }
        return Err("conflicting delivery below projection frontier".into());
    }
    if let Some(existing) = state
        .pending
        .iter()
        .find(|candidate| candidate.position == event.position)
    {
        if existing.evidence == event.evidence {
            return Ok(());
        }
        return Err("conflicting pending delivery".into());
    }
    if event_position > state.frontier.checked_add(1).ok_or("frontier overflows")? {
        state.pending.push(event);
        replace(path, &state)?;
        return Ok(());
    }
    let mut current = event;
    loop {
        let current_position = position(&current.position)?;
        if current_position != state.frontier.checked_add(1).ok_or("frontier overflows")? {
            return Err("non-contiguous delivery".into());
        }
        state.frontier = current_position;
        state.orders.push(current.order);
        state.applied.push(current.evidence);
        let next_position = state.frontier.checked_add(1).ok_or("frontier overflows")?;
        let Some(index) = state
            .pending
            .iter()
            .position(|candidate| position(&candidate.position) == Ok(next_position))
        else {
            break;
        };
        current = state.pending.remove(index);
    }
    replace(path, &state)?;
    if crash_after_apply {
        std::process::exit(86);
    }
    Ok(())
}

fn snapshot(state: &State) -> Result<Snapshot<Response<Vec<u8>>>, Box<dyn Error>> {
    let response = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .body(serde_json::to_vec(&json!({
            "frontier": state.frontier.to_string(),
            "orders": state.orders,
        }))?)?;
    let lineage = [(
        (ISSUER.into(), DOMAIN.into()),
        Mapping::Relevant {
            component_frontiers: vec![Frontier::At(state.frontier)],
            first_terminal_failure: None,
            progress_possible: true,
        },
    )]
    .into_iter()
    .collect::<BTreeMap<_, _>>();
    Ok(Snapshot::new(
        TARGET.into(),
        response,
        "typescript-source-rust-observer/v1".into(),
        "orders/v1".into(),
        lineage,
    )?)
}

fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|window| window == b"\r\n\r\n")
}

fn incoming(stream: &mut TcpStream) -> Result<Incoming, Box<dyn Error>> {
    let mut bytes = Vec::new();
    let mut buffer = [0; 1024];
    let header_end = loop {
        if let Some(index) = find_header_end(&bytes) {
            break index;
        }
        let count = stream.read(&mut buffer)?;
        if count == 0 {
            return Err("connection closed before HTTP headers".into());
        }
        bytes.extend_from_slice(&buffer[..count]);
        if bytes.len() > 16_384 {
            return Err("HTTP headers exceed test fixture limit".into());
        }
    };
    let head = std::str::from_utf8(&bytes[..header_end])?;
    let mut lines = head.split("\r\n");
    let mut request_line = lines.next().ok_or("missing HTTP request line")?.split(' ');
    let method = request_line.next().ok_or("missing HTTP method")?.to_owned();
    let path = request_line.next().ok_or("missing HTTP path")?.to_owned();
    if request_line.next() != Some("HTTP/1.1") || method.is_empty() || path.is_empty() {
        return Err("unsupported HTTP request line".into());
    }
    let headers = lines
        .map(|line| {
            let (name, value) = line.split_once(':').ok_or("invalid HTTP header")?;
            if name.is_empty() || value.contains('\r') || value.contains('\n') {
                return Err("invalid HTTP header".into());
            }
            Ok((name.to_owned(), value.trim().to_owned()))
        })
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    if headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("transfer-encoding"))
    {
        return Err("transfer encoding is not supported by this test fixture".into());
    }
    let length = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .map(|(_, value)| value.parse::<usize>())
        .transpose()?
        .unwrap_or(0);
    if length > 16_384 {
        return Err("HTTP body exceeds test fixture limit".into());
    }
    let mut body = bytes[(header_end + 4)..].to_vec();
    while body.len() < length {
        let count = stream.read(&mut buffer)?;
        if count == 0 {
            return Err("connection closed before HTTP body".into());
        }
        body.extend_from_slice(&buffer[..count]);
    }
    if body.len() != length {
        return Err("unexpected bytes after HTTP body".into());
    }
    Ok(Incoming {
        method,
        path,
        headers,
        body,
    })
}

fn request(incoming: &Incoming) -> Result<Request<()>, Box<dyn Error>> {
    let mut builder = Request::builder()
        .method(incoming.method.as_str())
        .uri(&incoming.path);
    for (name, value) in &incoming.headers {
        builder = builder.header(name, value);
    }
    Ok(builder.body(())?)
}

fn write_response(
    stream: &mut TcpStream,
    response: Response<Vec<u8>>,
) -> Result<(), Box<dyn Error>> {
    let (parts, body) = response.into_parts();
    write!(
        stream,
        "HTTP/1.1 {}\r\nConnection: close\r\nContent-Length: {}\r\n",
        parts.status,
        body.len()
    )?;
    for (name, value) in &parts.headers {
        write!(stream, "{}: {}\r\n", name, value.to_str()?)?;
    }
    write!(stream, "\r\n")?;
    stream.write_all(&body)?;
    Ok(())
}

fn plain(status: StatusCode) -> Response<Vec<u8>> {
    Response::builder()
        .status(status)
        .body(Vec::new())
        .expect("valid response")
}

fn serve_one(
    stream: &mut TcpStream,
    path: &Path,
    verifier: &Verifier,
    now: u64,
) -> Result<bool, Box<dyn Error>> {
    let incoming = incoming(stream)?;
    if incoming.method == "POST" && incoming.path == "/shutdown" {
        write_response(stream, plain(StatusCode::NO_CONTENT))?;
        return Ok(false);
    }
    if incoming.method == "POST"
        && matches!(
            incoming.path.as_str(),
            "/deliver" | "/deliver?crash-after-apply"
        )
    {
        let event = serde_json::from_slice(&incoming.body)?;
        return match deliver(
            path,
            verifier,
            event,
            now,
            incoming.path == "/deliver?crash-after-apply",
        ) {
            Ok(()) => {
                write_response(stream, plain(StatusCode::NO_CONTENT))?;
                Ok(true)
            }
            Err(error) => {
                eprintln!("persistent observer rejected delivery: {error}");
                write_response(stream, plain(StatusCode::BAD_REQUEST))?;
                Ok(true)
            }
        };
    }
    if incoming.method == "GET" && incoming.path == TARGET {
        let request = request(&incoming)?;
        let state = load(path)?;
        let response = match protocol_http::observe(
            ObservationOptions {
                request: &request,
                target: TARGET,
                designated_observation: true,
                verifier,
                authenticated_subject: SUBJECT,
            },
            || Ok::<bool, Infallible>(true),
            || now,
            || snapshot(&state).map_err(|error| error.to_string()),
        ) {
            Ok(response) => response,
            Err(error) => {
                eprintln!("persistent observer adapter failure: {error}");
                error.into_response()
            }
        };
        write_response(stream, response)?;
        return Ok(true);
    }
    write_response(stream, plain(StatusCode::NOT_FOUND))?;
    Ok(true)
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = arguments()?;
    let verifier = verifier()?;
    let listener = TcpListener::bind(&args.bind)?;
    println!("http://{}", listener.local_addr()?);
    std::io::stdout().flush()?;
    for incoming in listener.incoming() {
        let mut stream = incoming?;
        match serve_one(&mut stream, &args.state, &verifier, args.now) {
            Ok(true) => (),
            Ok(false) => return Ok(()),
            Err(error) => {
                let _ = write_response(&mut stream, plain(StatusCode::INTERNAL_SERVER_ERROR));
                eprintln!("persistent observer request failed: {error}");
            }
        }
    }
    Ok(())
}
