# Header Forensics — Setup Guide (Docker / platform-independent version)

This guide takes you from nothing to a running instance on any machine that
can run containers: Docker Desktop on Windows or macOS, Docker Engine or
Podman on Linux, a VPS, Kubernetes, or an air-gapped host.

## 1. Prerequisites

The only requirement is a container runtime. Install **Docker Desktop**
(Windows/macOS, https://www.docker.com/products/docker-desktop/) or
**Docker Engine** (Linux, `curl -fsSL https://get.docker.com | sh`).
Podman works too — substitute `podman` for `docker` in every command.
You do **not** need Node.js, npm, or any build tools on your machine;
the image builds the app inside a throwaway build stage.

Verify the runtime works:

```bash
docker version
```

## 2. Quick start (build from source)

```bash
git clone https://github.com/theatifquamar/email-header-analyzer.git
cd email-header-analyzer
docker build -t header-forensics .
docker run --rm -p 8080:8080 header-forensics
```

Open **http://localhost:8080**. That's the entire setup. Press `Ctrl+C`
to stop (the `--rm` flag removes the container afterwards).

To run it in the background instead:

```bash
docker run -d --name header-forensics --restart unless-stopped -p 8080:8080 header-forensics
```

## 3. Quick start (pull the prebuilt image — no clone, no build)

Once the GitHub Actions workflow in this repo has run on your fork/repo,
a multi-arch image (amd64 + arm64, so it also runs on Apple Silicon and
Raspberry Pi) is published to GitHub Container Registry. Anyone can then:

```bash
docker run -d --name header-forensics -p 8080:8080 \
  ghcr.io/theatifquamar/email-header-analyzer:latest
```

> First-time note: GHCR packages default to private. In the repository's
> **Packages → header-forensics → Package settings**, set visibility to
> **Public** so anonymous `docker pull` works.

## 4. Recommended: docker compose (hardened)

The included `docker-compose.yml` adds container hardening on top of the
already-unprivileged image: read-only root filesystem, all Linux
capabilities dropped, `no-new-privileges`, memory and PID limits.

```bash
docker compose up -d        # start
docker compose logs -f      # watch logs (errors only; access log is off)
docker compose down         # stop and remove
```

To use the GHCR image instead of building locally, comment out `build: .`
in the compose file and uncomment the `image:` line.

## 5. Verify the deployment

Confirm the security headers are being served (this is the part that
platform-hosted static files can get wrong — here it's baked in):

```bash
curl -sI http://localhost:8080 | grep -iE "content-security|x-frame|nosniff|referrer|permissions"
```

You should see the CSP with `connect-src` limited to `'self'`,
`dns.google`, and `cloudflare-dns.com`, plus `X-Frame-Options: DENY`,
`X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, and a
restrictive `Permissions-Policy`. In the app, click **load phishing
sample → Analyze headers** to confirm the analysis engine works end to end.

## 6. Exposing it publicly (TLS + HSTS)

The container serves plain HTTP on 8080 and is meant to sit behind a TLS
terminator when public. HSTS is deliberately not set inside the container
(it is meaningless on localhost and dangerous to emit blindly behind
unknown proxies) — enable it at the proxy. The simplest option is Caddy,
which provisions Let's Encrypt certificates automatically:

```caddy
# Caddyfile
headers.example.com {
    reverse_proxy 127.0.0.1:8080
    header Strict-Transport-Security "max-age=31536000; includeSubDomains"
}
```

Any equivalent works (nginx + certbot, Traefik, a cloud load balancer):
terminate TLS, forward to `:8080`, add the HSTS header. Everything else —
CSP, frame denial, nosniff, referrer and permissions policies, caching —
is already emitted by the container itself.

## 7. Offline / air-gapped use

The container needs no network at build-run boundary: after `docker build`
(or after `docker pull` + `docker save`/`docker load` to transfer the
image on removable media), it runs with **zero** internet access. In the
UI, untick **Live DNS enrichment** and the analysis is fully offline;
leave it ticked and the browser will simply fall back gracefully with the
missing lookups flagged as uncertainties. To make offline the default,
run the container with networking disabled entirely:

```bash
docker network create --internal isolated
docker run -d --network isolated -p 8080:8080 header-forensics   # or omit -p and use compose on an internal net
```

(Practically, `-p 8080:8080` on the default network is fine — the
container makes no outbound calls either way; DoH goes browser→resolver.)

## 8. Updating

```bash
git pull                       # or: docker pull ghcr.io/YOU/header-forensics:latest
docker compose up -d --build   # rebuild and replace in one step
```

Because assets are content-hashed and `index.html` is served with
`Cache-Control: no-store`, users get the new version on their next page
load with no cache-busting rituals.

## 9. Troubleshooting

**"port is already allocated"** — something else owns 8080. Map another
host port: `docker run -p 9090:8080 …` and browse to `:9090`.

**Page loads but DNS enrichment shows "unreachable"** — your network (not
the container) is blocking DNS-over-HTTPS to dns.google/cloudflare-dns.com;
common on corporate networks. The app degrades to header-only analysis by
design. Untick the option to silence the notice.

**Blank page behind a reverse proxy under a subpath** (e.g.
`https://tools.example.com/forensics/`) — the build uses relative asset
paths, so serve it from a dedicated hostname or a path that preserves the
directory (`/forensics/` with a trailing slash works; rewriting to `/`
does not need anything special).

**Podman rootless** — works as-is; the image already runs as uid 101 and
binds only 8080.

**Health status shows "unhealthy"** — check `docker logs header-forensics`;
the healthcheck simply fetches `/` every 30 s, so failures almost always
mean nginx couldn't start due to a mangled `docker/nginx.conf` edit.

## 10. What this container never does

No analysis data ever reaches the container: the app runs in the visitor's
browser and has no code path to send headers, results, or answers to the
server, and the browser-enforced CSP restricts outbound connections to the
two optional DoH resolvers only. The nginx access log is disabled, so the
container does not even record visitor IPs. Closing the browser tab
destroys all analysis state.
