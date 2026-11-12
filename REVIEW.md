---
lang: en-GB
---

# Plugin review and maintenance changes

Reviewed upstream commit `bcb87b41ceed4ee32d11169dc1b25ae6105d9ffb` (v0.10.0). This is a source review with targeted regression testing, not an independent security certification or an audit of KeePass itself.

## Findings addressed

| Priority | Finding | Change |
| --- | --- | --- |
| Required | An awaited result could change breach metadata after the password changed, the entry was removed, the database was switched or locked, or the plugin terminated. | Capture the database, root, live entry and immutable protected-password instance; validate before requests and before applying results. |
| Required | The global entry event also covers temporary editor and history copies, allowing unnecessary checks and alerts. | Require the exact live database entry, not merely a matching UUID. |
| Required | Timeouts raise cancellation exceptions that were not caught by the asynchronous UI handlers. | Handle request cancellation, use a 30-second timeout, cancel on termination and preserve breach metadata on failure. |
| Required | Empty, invalid and overflowing responses could be interpreted as a clean result; parsing relied on CRLF and case-sensitive substring searches. | Validate complete hash/count rows, support line-ending variations and case-insensitive exact suffix matching, retain zero-count padding semantics, and use non-negative 64-bit counts. |
| Required | Existing tagged entries retained obsolete breach counts; orphaned counts were never removed. | Update counts independently of tag changes, remove orphaned counts and mark modifications. |
| Required | Bulk scans counted skipped or failed entries as checked, under-reported progress and only marked the database dirty after all requests. | Count successful results, advance progress for skipped entries, mark the originating database dirty before the next request and report interrupted scans explicitly. |
| Required | Status logging could remain active following an exception. | End logging and clear the running state in `finally`. |
| Required | Disposing one client invalidated the static client used by other instances. | Give each plugin instance its own disposable HTTP client and configure headers once. |
| Required | Initialisation changed process-wide TLS policy; termination could fail after unsuccessful initialisation. | Scope TLS settings to the HTTP handler and make termination safe and idempotent. |
| Required | Optional entry-date changes used local time for KeePass UTC fields. | Use UTC, preserving the existing default of leaving dates unchanged. |
| Hardening | Plaintext UTF-8 password bytes remained in temporary managed memory after hashing. | Clear the temporary byte buffer in `finally`; this does not promise complete memory erasure. |
| Hardening | Overlapping requests duplicated work and could apply obsolete results. | Suppress duplicate checks for the same entry/password; allow a newly changed password to start its own check. |
| Hardening | HTTP redirects could send requests outside the configured endpoint. | Disable automatic redirects and reject non-success responses. |

The protocol still uses the [official HIBP range API](https://haveibeenpwned.com/API/v3#PwnedPasswords): only the five-character SHA-1 prefix is sent, response padding remains enabled, and suffix matching happens locally. No password/hash cache or additional runtime package was added. Manual single-entry checks continue to override ignore preferences; automatic and bulk checks respect them.

## Verification

- The original plugin and the changed plugin both built against the signed official KeePass 2.62 assembly, targeting .NET Framework 4.7.2.
- Final Release builds completed with zero warnings and zero errors.
- 55 offline regression checks passed using real KeePass entry/database classes, synthetic in-memory data and fake HTTP handlers/loggers.
- One additional live request using the documented HIBP example hash passed: 56 checks in total. Only its five-character prefix was sent.
- An initial 40-check subset was also run against the unmodified upstream source: 13 passed and 27 failed. Several checks exercise different cases of the same underlying issue; this is not a count of distinct vulnerabilities.
- Checks cover delayed responses, changed passwords, database switches/locks, removed/replaced entries, temporary clones, request duplication, HTTP failures/timeouts, malformed responses, metadata updates, progress, dirty-state timing and logging cleanup.
- The NuGet advisory check reported no known vulnerable direct or transitive packages in the configured advisory data. The existing build-only Nerdbank.GitVersioning package was retained.
- `git diff --check` is part of the final local checks. Source and tests are published; downloaded dependencies, binaries, local logs and test artefacts are excluded.

## Limits and recommendations

Interactive KeePass menu behaviour, modal alerts, save/lock/shutdown timing inside the real application, Linux/Mono and older .NET/Windows environments have not been validated. Test in an isolated KeePass copy with a disposable database before using a compiled build with important data. The harness does not open or save an existing password database.

This fork has no published binary release. Development builds disable update checks until a fork release and matching update manifest are prepared, preventing upstream version information from being mistaken for fork updates. Inherited installation links refer to the original upstream binaries.

Optional later improvements include a cancellable bulk-scan UI and clearer non-modal notifications. These are recommendations, not prerequisites for the correctness fixes. Automatic checks still run when live entries are modified, as configured upstream; this change does not introduce a new password-change-only trigger policy.

SHA-1 is required for the external HIBP range protocol and was not replaced. It is not used here as a database password-storage algorithm. No real credentials, databases or account-specific configuration are needed to reproduce these tests.
