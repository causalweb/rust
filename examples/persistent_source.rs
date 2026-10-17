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
    path::{Path, PathBuf},
};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use causalweb::evidence::{CommittedEvidence, Issuer, Limits, SigningKey};
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
    let mut interrupt_after_commit = false;
    while let Some(value) = values.next() {
        match value.as_str() {
            "--state" => state = Some(PathBuf::from(next_value(&mut values, "--state")?)),
            "--now" => now = Some(next_value(&mut values, "--now")?.parse()?),
            "--order" => order = Some(next_value(&mut values, "--order")?),
            "--recover" => recover = true,
            "--interrupt-after-commit" => interrupt_after_commit = true,
            _ => return Err(format!("unknown argument {value}").into()),
        }
    }
    let state = state.ok_or("--state is required")?;
    let now = now.ok_or("--now is required")?;
    let operation = match (order, recover) {
        (Some(order), false) => {
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
        (None, true) => Operation::Recover,
        _ => return Err("supply exactly one of --order or --recover".into()),
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

fn issuer() -> Result<Issuer, Box<dyn Error>> {
    let scalar = env::var("CAUSALWEB_DEMO_PRIVATE_KEY")?;
    let bytes = URL_SAFE_NO_PAD.decode(scalar)?;
    let key = SigningKey::from_slice(&bytes)?;
    Ok(Issuer::new(
        ISSUER.into(),
        KID.into(),
        key,
        [DOMAIN.into()].into_iter().collect(),
        LIFETIME,
        Limits::default(),
    )?)
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

fn main() -> Result<(), Box<dyn Error>> {
    let args = arguments()?;
    let mut state = load(&args.state)?;
    match args.operation {
        Operation::Commit {
            order,
            interrupt_after_commit,
        } => {
            let position = state.next_position;
            let event = Event {
                evidence_id: format!("urn:causalweb:persistent-source:{position}:{order}"),
                position,
                order,
                issued_at: args.now,
                expires_at: args
                    .now
                    .checked_add(LIFETIME)
                    .ok_or("expiration overflows")?,
                evidence: String::new(),
            };
            state.next_position = position.checked_add(1).ok_or("position overflows")?;
            state.events.push(event.clone());
            replace(&args.state, &state)?;
            if interrupt_after_commit {
                return Err("injected interruption after durable source commit".into());
            }
            let issued = evidence_for(&issuer()?, &event, args.now)?;
            *state
                .events
                .last_mut()
                .ok_or("committed event disappeared")? = issued.clone();
            replace(&args.state, &state)?;
            print(&state, Some(&issued))?;
        }
        Operation::Recover => {
            let issuer = issuer()?;
            let mut changed = false;
            for event in &mut state.events {
                if event.evidence.is_empty() {
                    *event = evidence_for(&issuer, event, args.now)?;
                    changed = true;
                }
            }
            if changed {
                replace(&args.state, &state)?;
            }
            print(&state, None)?;
        }
    }
    Ok(())
}
