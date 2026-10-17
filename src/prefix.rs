use std::collections::BTreeMap;

use serde::Serialize;

use crate::{Error, PROFILE, evidence::VerifiedEvidence};

pub fn position(value: &str) -> Result<u64, Error> {
    if value.is_empty()
        || value.len() > 20
        || !value.bytes().all(|b| b.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err(Error::InvalidEvidence);
    }
    value.parse().map_err(|_| Error::InvalidEvidence)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Frontier {
    Unknown,
    Bottom,
    At(u64),
}

#[derive(Clone, Debug)]
pub enum Mapping {
    Relevant {
        component_frontiers: Vec<Frontier>,
        first_terminal_failure: Option<u64>,
        progress_possible: bool,
    },
    /// Administrator-authorized exclusion, valid for this snapshot's schema and contract.
    Excluded {
        first_position: u64,
        last_position: u64,
    },
}

/// Representation and lineage must originate from the same immutable cut or transaction.
/// Construct only inside a trusted storage adapter, never from request metadata.
pub struct Snapshot<T> {
    pub(crate) target: String,
    pub(crate) representation: T,
    pub(crate) lineage: BTreeMap<(String, String), Mapping>,
    contract: String,
    schema: String,
}

impl<T> Snapshot<T> {
    pub fn new(
        target: String,
        representation: T,
        contract: String,
        schema: String,
        lineage: BTreeMap<(String, String), Mapping>,
    ) -> Result<Self, Error> {
        if target.is_empty() || contract.is_empty() || schema.is_empty() || lineage.values().any(|m|
            matches!(m, Mapping::Excluded { first_position, last_position } if first_position > last_position)) {
            return Err(Error::InvalidConfiguration);
        }
        Ok(Self {
            target,
            representation,
            lineage,
            contract,
            schema,
        })
    }
    pub fn target(&self) -> &str {
        &self.target
    }
    pub fn contract(&self) -> &str {
        &self.contract
    }
    pub fn schema(&self) -> &str {
        &self.schema
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Outcome {
    Satisfied,
    Unsatisfied,
    Unknown,
    Unsupported,
    Expired,
    Failed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Disposition {
    Applied,
    Irrelevant,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct Evaluation {
    pub outcome: Outcome,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disposition: Option<Disposition>,
    pub retryable: bool,
}

impl Evaluation {
    fn new(outcome: Outcome) -> Self {
        Self {
            outcome,
            disposition: None,
            retryable: false,
        }
    }
    fn satisfied(disposition: Disposition) -> Self {
        Self {
            outcome: Outcome::Satisfied,
            disposition: Some(disposition),
            retryable: false,
        }
    }
}

pub fn evaluate<T>(evidence: &VerifiedEvidence, snapshot: &Snapshot<T>, now: u64) -> Evaluation {
    if evidence.expired(now) {
        return Evaluation::new(Outcome::Expired);
    }
    if evidence.profile() != PROFILE {
        return Evaluation::new(Outcome::Unsupported);
    }
    let Some(mapping) = snapshot
        .lineage
        .get(&(evidence.issuer().to_owned(), evidence.domain().to_owned()))
    else {
        return Evaluation::new(Outcome::Unsupported);
    };
    let required = position(evidence.position()).expect("validated prefix position");
    match mapping {
        Mapping::Excluded {
            first_position,
            last_position,
        } => {
            if (*first_position..=*last_position).contains(&required) {
                Evaluation::satisfied(Disposition::Irrelevant)
            } else {
                Evaluation::new(Outcome::Unknown)
            }
        }
        Mapping::Relevant {
            component_frontiers,
            first_terminal_failure,
            progress_possible,
        } => {
            let covered = !component_frontiers.is_empty()
                && component_frontiers
                    .iter()
                    .all(|f| matches!(f, Frontier::At(p) if *p >= required));
            if covered {
                return Evaluation::satisfied(Disposition::Applied);
            }
            if first_terminal_failure.is_some_and(|p| p <= required) {
                return Evaluation::new(Outcome::Failed);
            }
            if component_frontiers.is_empty()
                || component_frontiers.contains(&Frontier::Unknown)
                || !progress_possible
            {
                return Evaluation::new(Outcome::Unknown);
            }
            Evaluation {
                retryable: true,
                ..Evaluation::new(Outcome::Unsatisfied)
            }
        }
    }
}
