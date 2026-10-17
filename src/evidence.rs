use std::collections::{BTreeMap, BTreeSet};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use p256::ecdsa::{
    Signature,
    signature::{Signer, Verifier as SignatureVerifier},
};
pub use p256::ecdsa::{SigningKey, VerifyingKey};
use serde_json::{Value, json};
use uriparse::URI;

use crate::{CLAIM, Error, PROFILE, json as strict_json, prefix::position};

pub const MAX_DATE: u64 = 9_007_199_254_740_991;

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub max_requirements: usize,
    pub max_header_bytes: usize,
    pub max_token_bytes: usize,
    pub max_decoded_bytes: usize,
    pub max_json_depth: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_requirements: 16,
            max_header_bytes: 16_384,
            max_token_bytes: 8_192,
            max_decoded_bytes: 8_192,
            max_json_depth: 32,
        }
    }
}

impl Limits {
    pub fn validate(&self) -> Result<(), Error> {
        if self.max_requirements == 0
            || self.max_header_bytes == 0
            || self.max_token_bytes == 0
            || self.max_decoded_bytes == 0
            || !(2..=64).contains(&self.max_json_depth)
        {
            return Err(Error::InvalidConfiguration);
        }
        Ok(())
    }
}

/// Local, administrator-supplied trust. No evidence-supplied key URLs are followed.
pub struct IssuerTrust {
    pub issuer: String,
    pub keys: BTreeMap<String, VerifyingKey>,
    pub domains: BTreeSet<String>,
    pub max_lifetime_seconds: u64,
    pub clock_skew_seconds: u64,
}

pub struct Verifier {
    audience: String,
    issuers: BTreeMap<String, IssuerTrust>,
    limits: Limits,
}

/// Authenticated only for the verifier policy and subject used for this exchange.
/// Create fresh evidence on each request; do not cache this across trust changes.
pub struct VerifiedEvidence {
    pub(crate) claims: Value,
    pub(crate) skew: u64,
}

impl VerifiedEvidence {
    pub fn issuer(&self) -> &str {
        self.claims["iss"].as_str().expect("validated issuer")
    }
    pub fn domain(&self) -> &str {
        self.claims[CLAIM]["domain"]
            .as_str()
            .expect("validated domain")
    }
    pub fn profile(&self) -> &str {
        self.claims[CLAIM]["profile"]
            .as_str()
            .expect("validated profile")
    }
    pub fn position(&self) -> &str {
        self.claims[CLAIM]["position"]
            .as_str()
            .expect("validated position")
    }
    pub fn expires_at(&self) -> u64 {
        strict_json::integer(&self.claims["exp"], MAX_DATE).expect("validated date")
    }
    pub fn expired(&self, now: u64) -> bool {
        u128::from(now) >= u128::from(self.expires_at()) + u128::from(self.skew)
    }
}

/// Returns the ordered indices of verified evidence a carrier must retain.
///
/// Callers verify every item under the current intended policy first, then use the indices to
/// retain their original compact evidence strings unchanged. `required_usable_until` is an
/// absolute UTC second through which a retained dominant item must remain usable. This function
/// does not issue, rewrite, or validate raw evidence and preserves every item it cannot safely
/// omit. The requested horizon cannot precede `now`.
pub fn retained_context_indices(
    evidence: &[VerifiedEvidence],
    now: u64,
    required_usable_until: u64,
) -> Result<Vec<usize>, Error> {
    if required_usable_until < now {
        return Err(Error::InvalidConfiguration);
    }
    Ok(evidence
        .iter()
        .enumerate()
        .filter_map(|(dominated_index, dominated)| {
            let omitted = evidence
                .iter()
                .enumerate()
                .any(|(candidate_index, candidate)| {
                    candidate_index != dominated_index
                        && dominates(candidate, dominated, now, required_usable_until)
                        && (position(candidate.position()).expect("validated position")
                            > position(dominated.position()).expect("validated position")
                            || candidate_index < dominated_index)
                });
            (!omitted).then_some(dominated_index)
        })
        .collect())
}

fn dominates(
    candidate: &VerifiedEvidence,
    dominated: &VerifiedEvidence,
    now: u64,
    required_usable_until: u64,
) -> bool {
    if candidate.expired(now) || dominated.expired(now) {
        return false;
    }
    let candidate_causal = &candidate.claims[CLAIM];
    let dominated_causal = &dominated.claims[CLAIM];
    let candidate_audiences = audience_values(&candidate.claims);
    let dominated_audiences = audience_values(&dominated.claims);
    candidate.claims["iss"] == dominated.claims["iss"]
        && candidate.claims["sub"] == dominated.claims["sub"]
        && strict_json::integer(&candidate_causal["v"], 1).expect("validated version")
            == strict_json::integer(&dominated_causal["v"], 1).expect("validated version")
        && candidate.profile() == PROFILE
        && candidate.profile() == dominated.profile()
        && candidate.domain() == dominated.domain()
        && candidate_causal["commit"] == dominated_causal["commit"]
        && candidate_audiences == dominated_audiences
        && position(candidate.position()).expect("validated position")
            >= position(dominated.position()).expect("validated position")
        && u128::from(candidate.expires_at()) + u128::from(candidate.skew)
            > u128::from(required_usable_until)
}

fn audience_values(claims: &Value) -> BTreeSet<&str> {
    match &claims["aud"] {
        Value::String(value) => BTreeSet::from([value.as_str()]),
        Value::Array(values) => values
            .iter()
            .map(|value| value.as_str().expect("validated audience"))
            .collect(),
        _ => unreachable!("validated audience"),
    }
}

fn absolute_uri(value: &str) -> bool {
    URI::try_from(value).is_ok()
}

fn https_issuer(value: &str) -> bool {
    URI::try_from(value).is_ok_and(|uri| {
        uri.scheme().as_str().eq_ignore_ascii_case("https")
            && uri
                .authority()
                .is_some_and(|a| !a.host().to_string().is_empty())
    })
}

fn common_claims(claims: &Value, max_lifetime: u64, skew: u64, now: u64) -> Result<(), Error> {
    let invalid = Error::InvalidEvidence;
    if !https_issuer(strict_json::string(claims, "iss")?) {
        return Err(invalid);
    }
    strict_json::string(claims, "sub")?;
    strict_json::string(claims, "jti")?;
    if claims.get("nbf").is_some() {
        return Err(invalid);
    }
    let audiences = match &claims["aud"] {
        Value::String(v) if !v.is_empty() => vec![v.as_str()],
        Value::Array(values) if !values.is_empty() => values
            .iter()
            .map(|v| v.as_str().filter(|s| !s.is_empty()).ok_or(invalid))
            .collect::<Result<Vec<_>, _>>()?,
        _ => return Err(invalid),
    };
    if audiences.iter().copied().collect::<BTreeSet<_>>().len() != audiences.len() {
        return Err(invalid);
    }
    let iat = strict_json::integer(&claims["iat"], MAX_DATE)?;
    let exp = strict_json::integer(&claims["exp"], MAX_DATE)?;
    if exp <= iat
        || exp - iat > max_lifetime
        || u128::from(iat) > u128::from(now) + u128::from(skew)
    {
        return Err(invalid);
    }
    let causal = claims.get(CLAIM).filter(|v| v.is_object()).ok_or(invalid)?;
    if strict_json::integer(&causal["v"], 1)? != 1 || causal["commit"] != "stable" {
        return Err(invalid);
    }
    let profile = strict_json::string(causal, "profile")?;
    if !absolute_uri(profile) || !absolute_uri(strict_json::string(causal, "domain")?) {
        return Err(invalid);
    }
    let value = strict_json::string(causal, "position")?;
    if profile == PROFILE {
        position(value)?;
    }
    Ok(())
}

pub(crate) fn decode(segment: &str) -> Result<Vec<u8>, Error> {
    if segment.is_empty() {
        return Err(Error::InvalidEvidence);
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(segment)
        .map_err(|_| Error::InvalidEvidence)?;
    if URL_SAFE_NO_PAD.encode(&bytes) != segment {
        return Err(Error::InvalidEvidence);
    }
    Ok(bytes)
}

impl Verifier {
    pub fn new(audience: String, trusts: Vec<IssuerTrust>, limits: Limits) -> Result<Self, Error> {
        limits.validate()?;
        if audience.is_empty() || audience.len() > 2048 || trusts.is_empty() {
            return Err(Error::InvalidConfiguration);
        }
        let mut issuers = BTreeMap::new();
        for trust in trusts {
            if !https_issuer(&trust.issuer)
                || trust.keys.is_empty()
                || trust.keys.keys().any(String::is_empty)
                || trust.domains.iter().any(|d| !absolute_uri(d))
                || trust.max_lifetime_seconds == 0
            {
                return Err(Error::InvalidConfiguration);
            }
            if issuers.insert(trust.issuer.clone(), trust).is_some() {
                return Err(Error::InvalidConfiguration);
            }
        }
        Ok(Self {
            audience,
            issuers,
            limits,
        })
    }

    pub fn limits(&self) -> Limits {
        self.limits
    }
    pub fn audience(&self) -> &str {
        &self.audience
    }

    pub fn verify(
        &self,
        compact: &str,
        authenticated_subject: &str,
        now: u64,
    ) -> Result<VerifiedEvidence, Error> {
        if compact.len() > self.limits.max_token_bytes {
            return Err(Error::TooLarge);
        }
        let mut parts = compact.split('.');
        let h = parts.next().ok_or(Error::InvalidEvidence)?;
        let p = parts.next().ok_or(Error::InvalidEvidence)?;
        let s = parts.next().ok_or(Error::InvalidEvidence)?;
        if parts.next().is_some() {
            return Err(Error::InvalidEvidence);
        }
        let header_bytes = decode(h)?;
        let payload_bytes = decode(p)?;
        let signature_bytes = decode(s)?;
        if header_bytes.len() + payload_bytes.len() + signature_bytes.len()
            > self.limits.max_decoded_bytes
        {
            return Err(Error::TooLarge);
        }
        let header = strict_json::object(&header_bytes, self.limits.max_json_depth)?;
        let claims = strict_json::object(&payload_bytes, self.limits.max_json_depth)?;
        if header["alg"] != "ES256"
            || header["typ"] != "cw-evidence+jwt"
            || header
                .as_object()
                .expect("object")
                .keys()
                .any(|k| !["alg", "kid", "typ"].contains(&k.as_str()))
        {
            return Err(Error::InvalidEvidence);
        }
        let issuer = strict_json::string(&claims, "iss")?;
        let trust = self.issuers.get(issuer).ok_or(Error::InvalidEvidence)?;
        let key = trust
            .keys
            .get(strict_json::string(&header, "kid")?)
            .ok_or(Error::InvalidEvidence)?;
        let signature =
            Signature::from_slice(&signature_bytes).map_err(|_| Error::InvalidEvidence)?;
        key.verify(format!("{h}.{p}").as_bytes(), &signature)
            .map_err(|_| Error::InvalidEvidence)?;
        common_claims(
            &claims,
            trust.max_lifetime_seconds,
            trust.clock_skew_seconds,
            now,
        )?;
        let audience_matches = match &claims["aud"] {
            Value::String(v) => v == &self.audience,
            Value::Array(v) => v.iter().any(|a| a.as_str() == Some(&self.audience)),
            _ => false,
        };
        if !audience_matches
            || authenticated_subject.is_empty()
            || claims["sub"] != authenticated_subject
            || !trust
                .domains
                .contains(strict_json::string(&claims[CLAIM], "domain")?)
        {
            return Err(Error::InvalidEvidence);
        }
        Ok(VerifiedEvidence {
            claims,
            skew: trust.clock_skew_seconds,
        })
    }
}

/// Signing component. The adapter MUST establish durable commitment before calling it.
/// This type has no database and cannot establish commitment or allocate positions.
pub struct Issuer {
    issuer: String,
    kid: String,
    key: SigningKey,
    domains: BTreeSet<String>,
    max_lifetime: u64,
    limits: Limits,
}

/// A stable source fact established by the application's storage adapter.
///
/// Positions are native `u64` values here and canonical decimal strings on the wire.
/// Dates are integral UTC seconds, limited to [`MAX_DATE`]. `evidence_id` must be
/// globally unique; neither an operation identifier nor an allocated position alone
/// necessarily has that property. The issuer checks syntax, authority, and time
/// policy, but cannot check whether the fact or its recovery information committed.
pub struct CommittedEvidence<'a> {
    pub subject: &'a str,
    pub audiences: &'a [&'a str],
    pub domain: &'a str,
    pub position: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub evidence_id: &'a str,
}

impl Issuer {
    pub fn new(
        issuer: String,
        kid: String,
        key: SigningKey,
        domains: BTreeSet<String>,
        max_lifetime: u64,
        limits: Limits,
    ) -> Result<Self, Error> {
        limits.validate()?;
        if !https_issuer(&issuer)
            || kid.is_empty()
            || domains.is_empty()
            || domains.iter().any(|d| !absolute_uri(d))
            || max_lifetime == 0
        {
            return Err(Error::InvalidConfiguration);
        }
        Ok(Self {
            issuer,
            kid,
            key,
            domains,
            max_lifetime,
            limits,
        })
    }

    /// Issue prefix evidence only after source commitment and recovery are established.
    ///
    /// This API constructs the protocol envelope; callers do not supply JSON claims,
    /// algorithms, versions, or commitment/profile markers. It rejects empty or
    /// duplicate audiences, unauthorized domains, invalid dates, and expired facts.
    ///
    /// ```
    /// use causalweb::evidence::CommittedEvidence;
    /// let fact = CommittedEvidence {
    ///     subject: "tenant-42", audiences: &["orders-view"],
    ///     domain: "https://source.example/domains/orders/epoch-1", position: 5,
    ///     issued_at: 100, expires_at: 200,
    ///     evidence_id: "urn:uuid:243041f2-27e4-4ff4-8767-d20148b9e514",
    /// };
    /// assert_eq!(fact.position, 5);
    /// ```
    pub fn issue_committed(&self, fact: &CommittedEvidence<'_>, now: u64) -> Result<String, Error> {
        let claims = json!({
            "iss": self.issuer, "sub": fact.subject, "aud": fact.audiences,
            "iat": fact.issued_at, "exp": fact.expires_at, "jti": fact.evidence_id,
            CLAIM: { "v": 1, "profile": PROFILE, "domain": fact.domain,
                "position": fact.position.to_string(), "commit": "stable" }
        });
        let payload = serde_json::to_vec(&claims).map_err(|_| Error::InvalidEvidence)?;
        if payload.len() > self.limits.max_decoded_bytes {
            return Err(Error::TooLarge);
        }
        let claims = strict_json::object(&payload, self.limits.max_json_depth)?;
        common_claims(&claims, self.max_lifetime, 0, now)?;
        if claims["iss"] != self.issuer
            || claims[CLAIM]["profile"] != PROFILE
            || !self
                .domains
                .contains(strict_json::string(&claims[CLAIM], "domain")?)
            || strict_json::integer(&claims["exp"], MAX_DATE)? <= now
        {
            return Err(Error::InvalidEvidence);
        }
        let header =
            serde_json::to_vec(&json!({"alg":"ES256", "kid":self.kid, "typ":"cw-evidence+jwt"}))
                .map_err(|_| Error::InvalidEvidence)?;
        if header.len() + payload.len() + 64 > self.limits.max_decoded_bytes {
            return Err(Error::TooLarge);
        }
        let signing_input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header),
            URL_SAFE_NO_PAD.encode(payload)
        );
        let signature: Signature = self.key.sign(signing_input.as_bytes());
        let token = format!(
            "{signing_input}.{}",
            URL_SAFE_NO_PAD.encode(signature.to_bytes())
        );
        if token.len() > self.limits.max_token_bytes {
            return Err(Error::TooLarge);
        }
        Ok(token)
    }
}
