//! Local, POSIX-only test source for cross-runtime recovery experiments.
//!
//! The private signing scalar is supplied by `CAUSALWEB_DEMO_PRIVATE_KEY` as an
//! unpadded base64url P-256 scalar. It is deliberately never written to the
//! source state. This example has a fixed test identity and clock supplied on
//! the command line; it is not a key-management or storage adapter.

use std::{
    env,
    error::Error,
    fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use causalweb::evidence::{CommittedEvidence, Issuer, Limits, SigningKey};
use p256::ecdsa::{Signature, signature::Signer};
use serde::{Deserialize, Serialize};

const ISSUER: &str = "https://orders.example";
const KID: &str = "persistent-demo";
const SUBJECT: &str = "tenant-example";
const AUDIENCE: &str = "https://orders-view.example/causal";
const DOMAIN: &str = "https://orders.example/domains/orders";
const LIFETIME: u64 = 3600;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct Event {
    evidence_id: String,
    position: u64,
    order: String,
    issued_at: u64,
    expires_at: u64,
    evidence: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct State {
    next_position: u64,
    events: Vec<Event>,
}

impl Default for State {
    fn default() -> Self {
        Self {
            next_position: 1,
            events: Vec::new(),
        }
    }
}

#[derive(Debug)]
struct Arguments {
    state: PathBuf,
    now: u64,
    operation: Operation,
}

#[derive(Debug)]
enum Operation {
    Commit {
        order: String,
        interrupt_after_commit: bool,
    },
    Recover,
    Serve {
        bind: String,
    },
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
    let mut order = None;
    let mut recover = false;
    let mut bind = None;
    let mut interrupt_after_commit = false;
    while let Some(value) = values.next() {
        match value.as_str() {
            "--state" => state = Some(PathBuf::from(next_value(&mut values, "--state")?)),
            "--now" => now = Some(next_value(&mut values, "--now")?.parse()?),
            "--order" => order = Some(next_value(&mut values, "--order")?),
            "--recover" => recover = true,
            "--listen" => bind = Some(next_value(&mut values, "--listen")?),
            "--interrupt-after-commit" => interrupt_after_commit = true,
            _ => return Err(format!("unknown argument {value}").into()),
        }
    }
    let state = state.ok_or("--state is required")?;
    let now = now.ok_or("--now is required")?;
    let operation = match (order, recover, bind) {
        (Some(order), false, None) => {
            if order.is_empty()
                || !order
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            {
                return Err("--order must use lowercase ASCII letters, digits, or hyphens".into());
            }
            Operation::Commit {
                order,
                interrupt_after_commit,
            }
        }
        (None, true, None) => Operation::Recover,
        (None, false, Some(bind)) => Operation::Serve { bind },
        _ => return Err("supply exactly one of --order, --recover, or --listen".into()),
    };
    Ok(Arguments {
        state,
        now,
        operation,
    })
}

fn load(path: &Path) -> Result<State, Box<dyn Error>> {
    match fs::read(path) {
        Ok(bytes) => Ok(serde_json::from_slice(&bytes)?),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(State::default()),
        Err(error) => Err(error.into()),
    }
}

// POSIX rename atomically replaces the prior document. This intentionally has no
// Windows fallback: the cross-runtime peer experiment runs on Linux, and a
// production adapter needs a storage-specific crash-consistency design.
#[cfg(not(unix))]
fn replace(_path: &Path, _state: &State) -> Result<(), Box<dyn Error>> {
    Err("persistent_source requires POSIX atomic rename semantics".into())
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

fn signing_key() -> Result<SigningKey, Box<dyn Error>> {
    let scalar = env::var("CAUSALWEB_DEMO_PRIVATE_KEY")?;
    let bytes = URL_SAFE_NO_PAD.decode(scalar)?;
    Ok(SigningKey::from_slice(&bytes)?)
}

fn issuer() -> Result<Issuer, Box<dyn Error>> {
    Ok(Issuer::new(
        ISSUER.into(),
        KID.into(),
        signing_key()?,
        [DOMAIN.into()].into_iter().collect(),
        LIFETIME,
        Limits::default(),
    )?)
}

/// Application-test delivery integrity envelope. It is not Causal Web evidence
/// or a protocol field; it lets the TypeScript peer reject a changed event
/// before the peer fixture updates its projection document.
fn delivery(event: &Event) -> Result<serde_json::Value, Box<dyn Error>> {
    let header = serde_json::to_vec(&serde_json::json!({
        "alg": "ES256",
        "kid": KID,
        "typ": "causalweb-demo-delivery+jwt"
    }))?;
    let payload = serde_json::to_vec(event)?;
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header),
        URL_SAFE_NO_PAD.encode(&payload)
    );
    let signature: Signature = signing_key()?.sign(input.as_bytes());
    let mut value = serde_json::to_value(event)?;
    value
        .as_object_mut()
        .ok_or("serialized event is not an object")?
        .insert(
            "deliveryProof".into(),
            serde_json::Value::String(format!(
                "{input}.{}",
                URL_SAFE_NO_PAD.encode(signature.to_bytes())
            )),
        );
    Ok(value)
}

fn evidence_for(issuer: &Issuer, event: &Event, now: u64) -> Result<Event, Box<dyn Error>> {
    let audiences = [AUDIENCE];
    Ok(Event {
        evidence: issuer.issue_committed(
            &CommittedEvidence {
                subject: SUBJECT,
                audiences: &audiences,
                domain: DOMAIN,
                position: event.position,
                issued_at: event.issued_at,
                expires_at: event.expires_at,
                evidence_id: &event.evidence_id,
            },
            now,
        )?,
        ..event.clone()
    })
}

fn print(state: &State, event: Option<&Event>) -> Result<(), Box<dyn Error>> {
    println!(
        "{}",
        serde_json::to_string(&serde_json::json!({
            "test_only": true,
            "issuer": ISSUER,
            "kid": KID,
            "subject": SUBJECT,
            "audience": AUDIENCE,
            "domain": DOMAIN,
            "event": event,
            "events": state.events,
        }))?
    );
    Ok(())
}

fn commit(
    path: &Path,
    now: u64,
    order: String,
    interrupt_after_commit: bool,
) -> Result<(State, Event), Box<dyn Error>> {
    let mut state = load(path)?;
    let position = state.next_position;
    let event = Event {
        evidence_id: format!("urn:causalweb:persistent-source:{position}:{order}"),
        position,
        order,
        issued_at: now,
        expires_at: now.checked_add(LIFETIME).ok_or("expiration overflows")?,
        evidence: String::new(),
    };
    state.next_position = position.checked_add(1).ok_or("position overflows")?;
    state.events.push(event.clone());
    replace(path, &state)?;
    if interrupt_after_commit {
        return Err("injected interruption after durable source commit".into());
    }
    let issued = evidence_for(&issuer()?, &event, now)?;
    *state
        .events
        .last_mut()
        .ok_or("committed event disappeared")? = issued.clone();
    replace(path, &state)?;
    Ok((state, issued))
}

fn recover(path: &Path, now: u64) -> Result<State, Box<dyn Error>> {
    let mut state = load(path)?;
    let issuer = issuer()?;
    let mut changed = false;
    for event in &mut state.events {
        if event.evidence.is_empty() {
            *event = evidence_for(&issuer, event, now)?;
            changed = true;
        }
    }
    if changed {
        replace(path, &state)?;
    }
    Ok(state)
}

fn headers(stream: &mut TcpStream) -> Result<String, Box<dyn Error>> {
    let mut bytes = Vec::new();
    let mut buffer = [0; 1024];
    while !bytes.ends_with(b"\r\n\r\n") {
        let count = stream.read(&mut buffer)?;
        if count == 0 {
            return Err("connection closed before HTTP headers".into());
        }
        bytes.extend_from_slice(&buffer[..count]);
        if bytes.len() > 16_384 {
            return Err("HTTP headers exceed test fixture limit".into());
        }
    }
    Ok(String::from_utf8(bytes)?)
}

fn response(
    stream: &mut TcpStream,
    status: &str,
    body: &[u8],
    causal_context: Option<&str>,
) -> Result<(), Box<dyn Error>> {
    let context = causal_context
        .map(|token| format!("Causal-Context: \"{token}\"\r\nCache-Control: private, no-store\r\n"))
        .unwrap_or_default();
    write!(
        stream,
        "HTTP/1.1 {status}\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{context}\r\n",
        body.len()
    )?;
    stream.write_all(body)?;
    Ok(())
}

fn serve_one(stream: &mut TcpStream, path: &Path, now: u64) -> Result<bool, Box<dyn Error>> {
    let request = headers(stream)?;
    let request_line = request.lines().next().ok_or("missing HTTP request line")?;
    if request_line == "POST /shutdown HTTP/1.1" {
        response(stream, "204 No Content", &[], None)?;
        return Ok(false);
    }
    if request_line == "POST /recover HTTP/1.1" {
        let state = recover(path, now)?;
        response(stream, "200 OK", &serde_json::to_vec(&state.events)?, None)?;
        return Ok(true);
    }
    let Some(order) = request_line
        .strip_prefix("POST /orders/")
        .and_then(|value| value.strip_suffix(" HTTP/1.1"))
    else {
        response(stream, "404 Not Found", b"{}", None)?;
        return Ok(true);
    };
    if order.is_empty()
        || !order
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        response(stream, "400 Bad Request", b"{}", None)?;
        return Ok(true);
    }
    let (_, event) = commit(path, now, order.into(), false)?;
    response(
        stream,
        "201 Created",
        &serde_json::to_vec(&delivery(&event)?)?,
        Some(&event.evidence),
    )?;
    Ok(true)
}

fn serve(path: &Path, now: u64, bind: &str) -> Result<(), Box<dyn Error>> {
    let listener = TcpListener::bind(bind)?;
    println!("http://{}", listener.local_addr()?);
    std::io::stdout().flush()?;
    for incoming in listener.incoming() {
        let mut stream = incoming?;
        match serve_one(&mut stream, path, now) {
            Ok(true) => (),
            Ok(false) => return Ok(()),
            Err(error) => {
                let _ = response(&mut stream, "500 Internal Server Error", b"{}", None);
                eprintln!("persistent source request failed: {error}");
            }
        }
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = arguments()?;
    match args.operation {
        Operation::Commit {
            order,
            interrupt_after_commit,
        } => {
            let (state, issued) = commit(&args.state, args.now, order, interrupt_after_commit)?;
            print(&state, Some(&issued))?;
        }
        Operation::Recover => {
            let state = recover(&args.state, args.now)?;
            print(&state, None)?;
        }
        Operation::Serve { bind } => serve(&args.state, args.now, &bind)?,
    }
    Ok(())
}
