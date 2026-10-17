#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

pub mod evidence;
pub mod http;
mod json;
pub mod prefix;

#[cfg(feature = "axum-0_8")]
pub mod axum;

use std::fmt;

pub const PROFILE: &str = "https://github.com/causalweb/spec/profiles/prefix-01";
pub const CLAIM: &str = "https://github.com/causalweb/spec/claims/v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidEvidence,
    InvalidRequirements,
    TooLarge,
    NotObservation,
    InvalidConfiguration,
    Unconfirmed,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidEvidence => "invalid causal evidence",
            Self::InvalidRequirements => "invalid causal requirements",
            Self::TooLarge => "causal request exceeds configured limits",
            Self::NotObservation => "endpoint is not a supported observation",
            Self::InvalidConfiguration => "invalid local protocol configuration",
            Self::Unconfirmed => "response does not confirm the causal requirements",
        })
    }
}

impl std::error::Error for Error {}
