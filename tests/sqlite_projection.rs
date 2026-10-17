//! Narrow SQLite transaction experiment, not a reusable storage adapter.
//!
//! The source and observer intentionally use different database files. The test
//! exercises the library's public issuer and observer APIs around two explicit
//! transactional boundaries: source fact plus outbox, and response bytes plus
//! projection frontier.

mod common;

use causalweb::{
    evidence::{Issuer, SigningKey, Verifier},
    http as cw_http,
    prefix::{Frontier, Mapping, Snapshot},
};
use common::*;
use http::{Request, Response, StatusCode};
use p256::elliptic_curve::Generate;
use rusqlite::{Connection, params};
use std::{
    collections::BTreeMap,
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

fn database_path(label: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "causalweb-rust-{label}-{}-{nonce}.sqlite",
        std::process::id()
    ))
}

fn initialize_source(connection: &Connection) -> rusqlite::Result<()> {
    connection.execute_batch(
        "
        CREATE TABLE source_facts (order_id TEXT PRIMARY KEY NOT NULL, body BLOB NOT NULL);
        CREATE TABLE source_outbox (position INTEGER PRIMARY KEY NOT NULL, order_id TEXT NOT NULL);
        ",
    )
}

fn initialize_projection(connection: &Connection) -> rusqlite::Result<()> {
    connection.execute_batch(
        "
        CREATE TABLE projection (
            target TEXT PRIMARY KEY NOT NULL,
            response_bytes BLOB NOT NULL,
            source_frontier INTEGER NOT NULL
        );
        INSERT INTO projection(target, response_bytes, source_frontier)
            VALUES ('/orders/123', x'5b5d', -1);
        ",
    )
}

fn commit_source(
    connection: &mut Connection,
    issuer: &Issuer,
    position: u64,
    order_id: &str,
    body: &[u8],
) -> rusqlite::Result<String> {
    let position = i64::try_from(position).expect("test position fits SQLite integer");
    let transaction = connection.transaction()?;
    transaction.execute(
        "INSERT INTO source_facts(order_id, body) VALUES (?1, ?2)",
        params![order_id, body],
    )?;
    transaction.execute(
        "INSERT INTO source_outbox(position, order_id) VALUES (?1, ?2)",
        params![position, order_id],
    )?;
    transaction.commit()?;

    // Evidence is created only after the database commits both source records.
    Ok(issuer
        .issue_committed(
            &committed(u64::try_from(position).expect("nonnegative source position")),
            100,
        )
        .expect("committed source fact is issuable"))
}

fn interrupt_projection_before_commit(
    connection: &mut Connection,
    response_bytes: &[u8],
    position: u64,
) -> rusqlite::Result<()> {
    let position = i64::try_from(position).expect("test position fits SQLite integer");
    let transaction = connection.transaction()?;
    transaction.execute(
        "UPDATE projection SET response_bytes = ?1 WHERE target = '/orders/123'",
        params![response_bytes],
    )?;
    transaction.execute(
        "UPDATE projection SET source_frontier = ?1 WHERE target = '/orders/123'",
        params![position],
    )?;
    // Simulate an interruption before the transaction's commit boundary.
    drop(transaction);
    Ok(())
}

fn apply_projection(
    connection: &mut Connection,
    response_bytes: &[u8],
    position: u64,
) -> rusqlite::Result<()> {
    let transaction = connection.transaction()?;
    let current: i64 = transaction.query_row(
        "SELECT source_frontier FROM projection WHERE target = '/orders/123'",
        [],
        |row| row.get(0),
    )?;
    let position = i64::try_from(position).expect("test position fits SQLite integer");
    if position <= current {
        return transaction.commit(); // Idempotent duplicate delivery.
    }
    assert_eq!(
        position,
        current + 1,
        "projection must not skip a source position"
    );
    transaction.execute(
        "UPDATE projection SET response_bytes = ?1 WHERE target = '/orders/123'",
        params![response_bytes],
    )?;
    transaction.execute(
        "UPDATE projection SET source_frontier = ?1 WHERE target = '/orders/123'",
        params![position],
    )?;
    transaction.commit()
}

fn snapshot(connection: &mut Connection) -> rusqlite::Result<Snapshot<Response<Vec<u8>>>> {
    let transaction = connection.transaction()?;
    let (bytes, frontier): (Vec<u8>, i64) = transaction.query_row(
        "SELECT response_bytes, source_frontier FROM projection WHERE target = '/orders/123'",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let frontier = if frontier < 0 {
        Frontier::Bottom
    } else {
        Frontier::At(u64::try_from(frontier).expect("nonnegative SQLite frontier"))
    };
    let snapshot = Snapshot::new(
        TARGET.into(),
        Response::new(bytes),
        "orders-projection/v1".into(),
        "orders-view/v1".into(),
        BTreeMap::from([(
            (ISSUER.into(), DOMAIN.into()),
            Mapping::Relevant {
                component_frontiers: vec![frontier],
                first_terminal_failure: None,
                progress_possible: true,
            },
        )]),
    )
    .expect("fixed adapter configuration is valid");
    transaction.commit()?;
    Ok(snapshot)
}

fn observe(
    request: &Request<()>,
    verifier: &Verifier,
    projection: &mut Connection,
) -> Response<Vec<u8>> {
    cw_http::observe::<_, _, _, (), rusqlite::Error>(
        cw_http::ObservationOptions {
            request,
            target: TARGET,
            designated_observation: true,
            verifier,
            authenticated_subject: SUBJECT,
        },
        || Ok(true),
        || 100,
        || snapshot(projection),
    )
    .expect("SQLite read is available")
}

#[test]
fn sqlite_source_outbox_and_projection_frontier_share_transactional_cuts() {
    let source_path = database_path("source");
    let projection_path = database_path("projection");
    let signing_key = SigningKey::generate();
    let verifier = verifier(*signing_key.verifying_key());
    let issuer = issuer(signing_key);

    let mut source = Connection::open(&source_path).unwrap();
    initialize_source(&source).unwrap();
    {
        let transaction = source.transaction().unwrap();
        transaction
            .execute(
                "INSERT INTO source_facts(order_id, body) VALUES ('aborted', x'7b7d')",
                [],
            )
            .unwrap();
        transaction
            .execute(
                "INSERT INTO source_outbox(position, order_id) VALUES (0, 'aborted')",
                [],
            )
            .unwrap();
        // The operation is interrupted before source commit; no token is issued.
    }
    assert_eq!(
        source
            .query_row("SELECT COUNT(*) FROM source_outbox", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        0
    );

    let token = commit_source(&mut source, &issuer, 0, "123", br#"{"order":"123"}"#).unwrap();
    drop(source);
    let source = Connection::open(&source_path).unwrap();
    assert_eq!(
        source
            .query_row("SELECT COUNT(*) FROM source_facts", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        1
    );
    assert_eq!(
        source
            .query_row("SELECT COUNT(*) FROM source_outbox", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        1
    );

    let mut request = Request::new(());
    *request.headers_mut() = cw_http::request_headers(&[token], limits()).unwrap();
    let mut projection = Connection::open(&projection_path).unwrap();
    initialize_projection(&projection).unwrap();
    assert_eq!(
        observe(&request, &verifier, &mut projection).status(),
        StatusCode::PRECONDITION_FAILED
    );

    interrupt_projection_before_commit(&mut projection, br#"{"order":"123"}"#, 0).unwrap();
    drop(projection);
    let mut projection = Connection::open(&projection_path).unwrap();
    let after_interruption = observe(&request, &verifier, &mut projection);
    assert_eq!(after_interruption.status(), StatusCode::PRECONDITION_FAILED);
    assert_ne!(
        after_interruption.headers().get(cw_http::RESULT),
        Some(&http::HeaderValue::from_static("satisfied"))
    );

    apply_projection(&mut projection, br#"{"order":"123"}"#, 0).unwrap();
    apply_projection(&mut projection, br#"{"order":"123"}"#, 0).unwrap();
    let confirmed = observe(&request, &verifier, &mut projection);
    assert_eq!(confirmed.status(), StatusCode::OK);
    cw_http::accept_confirmation(&confirmed, true).unwrap();
    assert_eq!(confirmed.body(), br#"{"order":"123"}"#);

    drop(projection);
    let mut projection = Connection::open(&projection_path).unwrap();
    let after_restart = observe(&request, &verifier, &mut projection);
    assert_eq!(after_restart.status(), StatusCode::OK);
    cw_http::accept_confirmation(&after_restart, true).unwrap();

    drop(projection);
    drop(source);
    fs::remove_file(source_path).unwrap();
    fs::remove_file(projection_path).unwrap();
}
