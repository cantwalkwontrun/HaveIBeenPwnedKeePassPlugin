---
lang: en-GB
---

# Security policy

This is a source-only development fork. No fork release binaries, reproducibility guarantees, mandatory collaborator settings or signed release claims are asserted here. The original project and its policy are available [upstream](https://github.com/kapsiR/HaveIBeenPwnedKeePassPlugin/blob/main/SECURITY.md).

A KeePass plugin runs inside the password manager and can access its open databases. Review plugins and obtain KeePass itself from [official sources](https://keepass.info/download.html). Protect the plugin directory against unauthorised modification; see [KeePass plugin guidance](https://keepass.info/help/v2/plugins.html).

This plugin queries the HIBP password range API over HTTPS with a five-character SHA-1 prefix and response padding. The remaining suffix is matched locally. SHA-1 here implements the external range protocol; it is not used to store database passwords. The API still receives the prefix and normal connection metadata, so k-anonymity is not a promise of complete anonymity.

See [REVIEW.md](./REVIEW.md) for the scope of the code review, tests and outstanding runtime validation. The review does not establish that the plugin is free from every vulnerability.

Development builds disable KeePass update checks until a fork release and matching update manifest exist. No automatic installer or uploader has been added.

For an upstream vulnerability, follow the original project's [private reporting instructions](https://github.com/kapsiR/HaveIBeenPwnedKeePassPlugin/security/advisories). Do not include real passwords, databases, credentials or other private data in public reports.
