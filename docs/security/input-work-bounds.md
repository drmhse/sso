# Input and expensive-work bounds

This is a source inventory, not throughput or denial-of-service qualification.
The limits below are local implementation evidence; reverse proxies, database
capacity, multiple replicas, and release hardware still need measured tests.

| Input or work | Trust source | Current bound | Evidence and remaining gap |
|---|---|---|---|
| JSON and URL-encoded request bodies | Internet clients and authenticated tenants | Streaming HTTP body limit, 1 MiB by default; whole-request timeout, 30 seconds | `api/src/http_security.rs`, `api/src/lib.rs`. Serde's parser rejects malformed/deep values, but SCIM group/PATCH operation counts and other large collection semantics need explicit endpoint limits and corpora. |
| SAML AuthnRequest and LogoutRequest XML | Internet service providers | 262,144 encoded bytes; 1,048,576 decoded bytes after raw DEFLATE; 32 element levels; 4,096 parser events; 64 attributes per element; 512 total attributes | `api/src/handlers/saml.rs` has deterministic byte/depth/event/attribute boundary corpora. Maintained fuzz targets, signature-work budgets, and external SP interoperability remain open. |
| SCIM filters and PATCH JSON | SCIM bearer clients | Global request-body/time limits; parser grammar and route validation | `api/crates/authos-services/src/services/scim_filter.rs`, `api/src/handlers/scim`. Add token/operation/member-count limits and deterministic malformed/deep corpora. |
| OAuth/OIDC and billing JSON responses | Configured external providers | 64 KiB response body, no redirects, pinned safe resolutions | `api/crates/authos-crypto/src/crypto/safe_http.rs`, Stripe/Polar/OAuth callers. Add slow-stream and DNS/proxy integration tests. |
| GeoIP gzip/tar download | Exact MaxMind HTTPS host after one constrained redirect | 128 MiB download, 256 MiB expanded stream, 128 MiB selected database; only the expected database is installed atomically | `api/crates/authos-services/src/services/geoip_setup.rs`. Add member-count/header corpora and measured extraction time. |
| Release and npm tar archives and metadata | Release CI/operator-provided local files | Standalone archives: 512 MiB compressed, 1 GiB expanded, 256 members. npm tarballs: 32 MiB compressed, 128 MiB expanded, 4,096 members, and 1 MiB `package.json`. Checksums are 64 KiB, manifests 1 MiB, and SPDX JSON 32 MiB. Path traversal, special-file, and expected identity checks also apply. | `scripts/verify-release-assets.py`, `scripts/npm-release-evidence.py` and boundary tests. These are offline supply-chain paths; add malformed-header/link corpora and measured verification time. |
| Password and MFA backup-code Argon2 | Internet/authenticated request fields | 1,024 UTF-8 input bytes, CPU-scaled shared semaphore, two-second permit queue, blocking-pool execution | `api/crates/authos-crypto/src/crypto/concurrency.rs` and request handlers. Publish measured overload/latency behavior and parameter-upgrade policy. |
| SAML RSA key generation | Authenticated service configuration | CPU-scaled semaphore capped at four, blocking-pool execution | `api/src/handlers/saml.rs`, `api/crates/authos-crypto/src/crypto/concurrency.rs`. Signing/verification work and HSM behavior remain unqualified. |
| JWT, SAML, WebAuthn, AES-GCM parsing/signing/verification | Internet tokens/assertions or encrypted database values | Global body/time bounds where HTTP-carried; algorithm/key/profile checks and ciphertext envelope lengths | Add per-format deterministic corpora, explicit token/certificate/key size limits where libraries do not already enforce them, and concurrency/load evidence. |

The next priority is explicit SCIM operation/member counts, followed by
maintained fuzz targets for SAML XML, SCIM filters, JWTs, and release-manifest/
archive metadata.
