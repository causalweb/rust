mod common;

use causalweb::{
    Error,
    evidence::{MAX_DATE, SigningKey},
};
use common::*;
use p256::elliptic_curve::Generate;

#[test]
fn typed_issuance_round_trips_the_entire_prefix_range() {
    let key = SigningKey::generate();
    let verifier = verifier(*key.verifying_key());
    let issuer = issuer(key);
    for position in [0, 1, 9_007_199_254_740_992, u64::MAX] {
        let token = issuer.issue_committed(&committed(position), 100).unwrap();
        let evidence = verifier.verify(&token, SUBJECT, 100).unwrap();
        assert_eq!(evidence.position(), position.to_string());
        assert_eq!(evidence.domain(), DOMAIN);
        assert_eq!(evidence.expires_at(), 1000);
    }
}

#[test]
fn typed_issuance_still_validates_semantic_constraints() {
    let issuer = issuer(SigningKey::generate());
    for fact in [
        causalweb::evidence::CommittedEvidence {
            subject: "",
            ..committed(5)
        },
        causalweb::evidence::CommittedEvidence {
            audiences: &[],
            ..committed(5)
        },
        causalweb::evidence::CommittedEvidence {
            audiences: &[AUDIENCE, AUDIENCE],
            ..committed(5)
        },
        causalweb::evidence::CommittedEvidence {
            domain: OTHER_DOMAIN,
            ..committed(5)
        },
        causalweb::evidence::CommittedEvidence {
            issued_at: 101,
            ..committed(5)
        },
        causalweb::evidence::CommittedEvidence {
            expires_at: 100,
            ..committed(5)
        },
        causalweb::evidence::CommittedEvidence {
            expires_at: MAX_DATE + 1,
            ..committed(5)
        },
        causalweb::evidence::CommittedEvidence {
            evidence_id: "",
            ..committed(5)
        },
    ] {
        assert_eq!(
            issuer.issue_committed(&fact, 100),
            Err(Error::InvalidEvidence)
        );
    }
}
