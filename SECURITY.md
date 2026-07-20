# Security Policy

Email Header Forensics is a security-analysis tool, so it's held to the
same standard it applies to the mail it inspects: report problems
responsibly, get a real response, and know what to expect.

## Supported versions

Only the `latest` released version (the most recent tag / the tip of
`main`) is supported. This is a small, actively-developed project without
the resources to backport fixes to older releases — please upgrade to the
latest version before reporting an issue.

## Reporting a vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**
Public issues are fine for bugs, feature requests, and general questions —
but a security report filed publicly gives potential attackers a head
start before a fix ships.

Instead, report privately using one of:

1. **GitHub Private Vulnerability Reporting** (preferred): go to the
   **Security** tab of this repository → **Report a vulnerability**. This
   opens a private advisory visible only to the maintainer until resolved.
2. **Direct contact**: reach the maintainer via
   [LinkedIn](https://www.linkedin.com/in/theatifquamar/) if the GitHub
   option isn't available to you.

Please include:
- A description of the issue and its potential impact.
- Steps to reproduce (a minimal example is ideal).
- The version/commit affected.
- Whether the issue is in the application logic (client-side JS), the
  container/deployment configuration, or a third-party dependency.

## What counts as in-scope

Given this project's architecture (a static client-side app with no
backend and no persisted data), the most relevant vulnerability classes are:

- **XSS or script injection** via crafted email headers being rendered
  unsafely anywhere in the UI.
- **CSP bypass** — any way for the page to make a network request outside
  the documented `connect-src` allow-list (which would undermine the
  core "nothing is sent anywhere without an explicit, named exception"
  privacy claim).
- **Supply-chain issues** in a dependency (currently: React, React-DOM,
  Vite, and their transitive dependencies) with a known exploitable CVE.
- **Container hardening regressions** — e.g., the Docker image losing its
  non-root user, read-only filesystem compatibility, or dropped
  capabilities.
- **Incorrect security-relevant analysis logic** — e.g., a scoring bug
  that would cause a clearly malicious sample to be marked "Legitimate."
  This is a correctness bug with security consequences, so it's treated
  as an in-scope report even though it isn't a traditional vulnerability.

Because this tool never sends analysis data to any server, classic
server-side vulnerability classes (SQLi, server-side RCE, auth bypass,
data-breach-via-backend) don't apply — there is no backend and no stored
user data to compromise.

## What to expect

- **Acknowledgment**: within a few days of a private report.
- **Assessment and fix timeline**: communicated once the report is
  triaged; severity drives priority, not a fixed SLA, given this is a
  community project without a dedicated security team.
- **Credit**: reporters are credited in the fix's release notes/changelog
  unless they prefer to remain anonymous — just say so in the report.
- **Disclosure**: coordinated disclosure once a fix is released. If a
  report goes unanswered for an extended period, reasonable public
  disclosure after good-faith attempts to reach the maintainer is
  understood, consistent with standard responsible-disclosure norms.

## Verifying release integrity

Published container images are signed keylessly via
[Sigstore/cosign](https://www.sigstore.dev/), tied to the GitHub Actions
workflow that built them — see `docs/SETUP.md` for the exact
`cosign verify` command. An SBOM (Software Bill of Materials) and build
provenance attestation are attached to every published image, so you can
inspect exactly what went into it rather than trusting this document's
word for it.
