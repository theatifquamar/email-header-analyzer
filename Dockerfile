# ============================================================
# Email Header Forensics — platform-independent container image
#
# Stage 1 builds the static bundle; Stage 2 serves it with an
# UNPRIVILEGED nginx (runs as non-root, listens on 8080).
# Final image ≈ 25 MB. No runtime network access is required.
#
#   docker build -t header-forensics .
#   docker run --rm -p 8080:8080 header-forensics
#   → http://localhost:8080
# ============================================================

# ---------- Stage 1: build ----------
FROM node:22-alpine AS build
WORKDIR /app

# Install exact, locked dependencies first (better layer caching)
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund

# Build the static bundle
COPY index.html vite.config.js ./
COPY public ./public
COPY src ./src
RUN npm run build

# ---------- Stage 2: runtime ----------
# nginx-unprivileged: master + workers run as uid 101 (non-root),
# listens on 8080 so no privileged ports or capabilities are needed.
FROM nginxinc/nginx-unprivileged:1.27-alpine

# Replace the default site with our hardened config (headers baked in)
COPY docker/nginx.conf /etc/nginx/conf.d/default.conf

# Static site
COPY --from=build /app/dist /usr/share/nginx/html

EXPOSE 8080

# Container-level liveness probe (wget ships with the alpine base)
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -q -O /dev/null http://127.0.0.1:8080/ || exit 1
