# Security policy

This implementation is experimental and has not received an independent security audit. Do not use it to promise production consistency or access-control freshness without reviewing the storage and transport obligations in [CONFORMANCE.md](CONFORMANCE.md).

The [dependency review snapshot](security/DEPENDENCIES.md) records advisory database/version, lockfile hash, and limitations. It is not external security review.

Report exploitable vulnerabilities privately at [GitHub Security Advisories](https://github.com/causalweb/rust/security/advisories/new). Do not put credentials, evidence from real tenants, private topology, or exploit details for active deployments in public issues. Maintainers coordinate remediation and disclosure with the reporter; no response SLA is promised.

## Trust boundaries

The implementation authenticates evidence using fixed ES256 and administrator-supplied issuer/key/domain mappings. It does not fetch untrusted key URLs. Canonical base64url, bounded JSON, duplicate names at every depth, common claims, audiences, subjects, lifetime, and expiry are checked before state selection in the observer helper.

The caller still owns current application authorization, TLS, route designation, CSRF and CORS, proxy limits, request cancellation, and log redaction. Supplying `authorize: || true` is appropriate only in synthetic tests or inside a separately enforced authorization boundary. Possession of evidence must never grant resource access.

Signing does not create a stable source fact. A frontier does not create a projection transaction. Exclusions and lineage must come from an authorized, versioned storage/projection contract and describe the exact response state. Malicious or incorrectly implemented issuers and adapters can lie despite valid signatures.

The library performs no deliberate waiting and no remote key retrieval. Hosts must bound concurrent requests, storage work, response sizes, key rotation, and retention. A deployment must refresh its verifier policy after revocation and must not reuse authenticated evidence objects across policy changes.
