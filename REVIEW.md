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

## Three-party follow-up review

Three separate source reviewers examined this plugin and the companion Dashboarder fork: security/privacy, robustness/lifecycle, and usability/theme compatibility. The implementing developer addressed their findings and ran the regression suite. Reviewers did not independently execute the tests or the real KeePass UI.

| Classification | Finding | Implemented fix |
| --- | --- | --- |
| Required | Entry changes during a bulk scan were discarded, including a password edited after its row had already been checked. | Queue the latest immutable check context per entry, then revalidate and drain it after bulk cleanup. Suspended checks, ignored entries and shutdown still take precedence. |
| Required | An earlier changed row made later unchanged results set the database dirty again after a save during the scan. | Mark the database dirty only for the current result's changes; retain a separate cumulative flag for final repainting. |
| Required | Repeated manual failures became silent after the first automatic outage. | Report each manual single-entry failure; deduplicate automatic warnings and preserve breach metadata. |
| Required | A range response had no practical buffer cap. | Reject responses over 2 MiB; the failure path preserves existing breach information. |
| Usability | Different copies of the plugin menu showed stale settings, and busy actions silently returned. | Synchronise option checkmarks and busy availability across all menu copies and when opening them; use clearer labels, including the runtime paused state. |

The companion Dashboarder fixes cover readable columns/window bounds, theme header contrast, multi-entry assignment, image ownership, bounded HTTP/decoding and download cancellation. Its own review records the detailed limits and verification.

## Verification

- The original plugin and the changed plugin both built against the signed official KeePass 2.62 assembly, targeting .NET Framework 4.7.2.
- Final Release builds completed with zero warnings and zero errors.
- 69 offline regression checks passed using real KeePass entry/database classes, synthetic in-memory data and fake HTTP handlers/loggers.
- One additional live request using the documented HIBP example hash passed: 70 checks in total. Only its five-character prefix was sent.
- An initial 40-check subset was also run against the unmodified upstream source: 13 passed and 27 failed. Several checks exercise different cases of the same underlying issue; this is not a count of distinct vulnerabilities.
- Checks cover delayed responses, changed passwords, database switches/locks, removed/replaced entries, temporary clones, request duplication, HTTP failures/timeouts, malformed responses, metadata updates, progress, dirty-state timing and logging cleanup.
- The NuGet advisory check reported no known vulnerable direct or transitive packages in the configured advisory data. The existing build-only Nerdbank.GitVersioning package was retained.
- `git diff --check` is part of the final local checks. Source and tests are published; downloaded dependencies, binaries, local logs and test artefacts are excluded.

## Companion-plugin compatibility

Automatic entry events can originate on worker threads in other plugins. They are now posted to the UI context captured during initialisation before reading entries, changing request bookkeeping, showing alerts or refreshing controls. Queued callbacks are ignored after termination. Four additional worker-event regression cases cover icon touches, duplicates, ignored entries and shutdown.

Metadata changes also invalidate the main window's child controls after refreshing entries. This lets details panels repaint live tags while preserving entry dates and selection. Bulk scans request this repaint when metadata changed.

Tests exercised the actual icon mutation methods from Custom Icon Dashboarder v1.3.0 and the companion maintenance build 1.4.0.0. The v1.3.0 PLGX source was extracted locally, and its source files matched the release tag; only its packaged project template differed.

The exact released Fluent Theme v1.5.2026.1111 DLL was checked against the release asset digest (`661d27062f0584afe39bd71dc118031355a4457fac4bbc3a85de67a49f93f474`). Its actual details panel rendered synthetic `pwned` tag additions/removals correctly off-screen in light and dark modes without changing entry dates. No third-party plugin source or DLL is bundled in this repository.

Optional fixture checks can be selected with `--dashboarder` followed by a Dashboarder test assembly path, or `--fluent` followed by the exact theme DLL path. These are supplied locally and are not downloaded by the test harness. Include `--live` for the additional synthetic HIBP request.

## Limits and recommendations

Interactive KeePass menu behaviour, modal alerts, save/lock/shutdown timing inside the real application, Linux/Mono and older .NET/Windows environments have not been validated. Test in an isolated KeePass copy with a disposable database before using a compiled build with important data. The harness does not open or save an existing password database.

This fork has no published binary release. Development builds disable update checks until a fork release and matching update manifest are prepared, preventing upstream version information from being mistaken for fork updates. Inherited installation links refer to the original upstream binaries.

Optional later improvements include a cancellable bulk-scan UI and clearer non-modal notifications. These are recommendations, not prerequisites for the correctness fixes. Automatic checks still run when live entries are modified, as configured upstream; this change does not introduce a new password-change-only trigger policy.

SHA-1 is required for the external HIBP range protocol and was not replaced. It is not used here as a database password-storage algorithm. No real credentials, databases or account-specific configuration are needed to reproduce these tests.
