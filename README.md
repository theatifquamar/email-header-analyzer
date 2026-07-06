# Header Forensics — Docker Edition

Privacy-first email header analysis for SOC analysts. SPF/DKIM/DMARC +
alignment, Received-chain reconstruction, FCrDNS/ASN enrichment, timestamp
forensics, ESP/gateway recognition, evidence-weighted verdicts, and
Markdown/PDF reports — **processed entirely in your browser**. The server
(this container) only ships static files and never receives analysis data.

## Run it

```bash
docker build -t header-forensics . && docker run --rm -p 8080:8080 header-forensics
# → http://localhost:8080
```

Or hardened, in the background:

```bash
docker compose up -d
```

Or pull the prebuilt multi-arch image (amd64 + arm64) once CI has published it:

```bash
docker run -d -p 8080:8080 ghcr.io/theatifquamar/email-header-analyzer:latest
```

Runs identically on Docker Desktop (Windows/macOS), Docker Engine or
rootless Podman (Linux), any VPS, Kubernetes, or fully air-gapped hosts.

## Why a container for a static site?

Security headers (CSP `frame-ancestors`, `X-Frame-Options`, HSTS) only work
as real HTTP headers. This image bakes an unprivileged nginx with the full
header policy into the artifact, so the security posture is guaranteed on
**any** platform — no `vercel.json`, no `_headers`, no host-specific config.

## Privacy guarantees

Analysis runs in tab memory only — no storage APIs, nothing persisted.
The browser-enforced CSP limits egress to two optional DNS-over-HTTPS
resolvers (IPs/domains only, toggleable off in the UI). The container
keeps **no access logs**. See `docs/IMPLEMENTATION.md` for the full
architecture and threat model, `docs/SETUP.md` for setup, TLS/HSTS,
air-gapped use, and troubleshooting, and `docs/architecture.png` for the
architecture diagram.
