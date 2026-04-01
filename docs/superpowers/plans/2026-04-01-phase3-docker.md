# Phase 3: Docker Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build production-grade Docker images (full, ghidra-only, radare2-only) so users can `docker run reverse-tool opcode ...` with zero setup.

**Architecture:** Single Dockerfile with multi-stage builds and 3 build targets. Base: python:3.12-slim-bookworm. JRE 21 (not JDK). Radare2 compiled from source. Non-root user.

**Tech Stack:** Docker multi-stage builds, Eclipse Temurin JRE 21, Ghidra 12.0.4, Radare2 6.1.2

**Depends on:** Phase 2 complete (65 tests, working CLI with opcode + function-call extractors)

---

## Version-Locked Artifacts

| Component | Version | Source |
|-----------|---------|--------|
| Python base | 3.12-slim-bookworm | Docker Hub |
| JRE | 21 (Temurin) | `eclipse-temurin:21-jre-jammy` |
| Ghidra | 12.0.4 | `ghidra_12.0.4_PUBLIC_20260303.zip` |
| Ghidra SHA256 | `c3b458661d69e26e203d739c0c82d143cc8a4a29d9e571f099c2cf4bda62a120` | |
| Ghidra URL | `https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.0.4_build/ghidra_12.0.4_PUBLIC_20260303.zip` | |
| Radare2 | 6.1.2 | Git tag from github.com/radareorg/radare2 |

---

## File Map

| File | Responsibility |
|------|---------------|
| `docker/Dockerfile` | Single multi-stage, multi-target Dockerfile |
| `docker/entrypoint.sh` | Smart entrypoint (route to reverse-tool or fallback) |
| `.dockerignore` | Exclude .git, .venv, tests, docs from build context |
| `docker/docker-compose.dev.yml` | Dev convenience (volume mounts) |

---

### Task 1: .dockerignore + Entrypoint

**Files:**
- Create: `.dockerignore`
- Create: `docker/entrypoint.sh`

- [ ] **Step 1: Write .dockerignore**

`.dockerignore`:
```
.git
.github
.venv
.mypy_cache
.pytest_cache
.ruff_cache
__pycache__
*.pyc
*.egg-info
dist/
build/
tests/
docs/
*.md
!README.md
!LICENSE
output/
samples/
```

- [ ] **Step 2: Write entrypoint**

`docker/entrypoint.sh`:
```bash
#!/bin/bash
set -euo pipefail

case "${1:-}" in
  reverse-tool)
    shift
    exec reverse-tool "$@"
    ;;
  bash|sh|r2|r2pm|rabin2|ragg2|rahash2|rafind2|rarun2|rax2|analyzeHeadless|python|python3)
    exec "$@"
    ;;
  -*)
    exec reverse-tool "$@"
    ;;
  *)
    exec reverse-tool "$@"
    ;;
esac
```

- [ ] **Step 3: Make entrypoint executable and commit**

```bash
chmod +x docker/entrypoint.sh
git add .dockerignore docker/entrypoint.sh
git commit -m "feat: add .dockerignore and smart entrypoint script"
```

---

### Task 2: Multi-Stage Dockerfile

**Files:**
- Create: `docker/Dockerfile`

- [ ] **Step 1: Write the Dockerfile**

`docker/Dockerfile`:
```dockerfile
# ==============================================================
# ReverseTool Docker Image
# Single Dockerfile with multi-stage builds and 3 targets:
#   full        — Ghidra + Radare2 (default)
#   ghidra-only — Ghidra only
#   radare2-only — Radare2 only
#
# Build:
#   docker build --target full -t reverse-tool:latest -f docker/Dockerfile .
#   docker build --target ghidra-only -t reverse-tool:ghidra -f docker/Dockerfile .
#   docker build --target radare2-only -t reverse-tool:radare2 -f docker/Dockerfile .
# ==============================================================

# --- Args (version-locked) ---
ARG PYTHON_VERSION=3.12
ARG RADARE2_VERSION=6.1.2
ARG GHIDRA_VERSION=12.0.4
ARG GHIDRA_DATE=20260303
ARG GHIDRA_SHA256=c3b458661d69e26e203d739c0c82d143cc8a4a29d9e571f099c2cf4bda62a120

# ==============================================================
# Stage 1: Python deps builder
# ==============================================================
FROM python:${PYTHON_VERSION}-slim-bookworm AS python-builder

WORKDIR /build
COPY pyproject.toml README.md LICENSE ./
COPY src/ ./src/

RUN pip install --no-cache-dir --prefix=/opt/python-deps .

# ==============================================================
# Stage 2: Radare2 builder (compile from source)
# ==============================================================
FROM python:${PYTHON_VERSION}-slim-bookworm AS radare2-builder

ARG RADARE2_VERSION

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    git \
    meson \
    ninja-build \
    pkg-config \
    libzip-dev \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 --branch ${RADARE2_VERSION} \
      https://github.com/radareorg/radare2.git /tmp/radare2 \
    && cd /tmp/radare2 \
    && meson setup build --prefix=/opt/radare2 \
         --buildtype=release \
         -Ddefault_library=shared \
    && ninja -C build \
    && ninja -C build install \
    && rm -rf /tmp/radare2

# Verify installation
RUN /opt/radare2/bin/r2 -v

# ==============================================================
# Stage 3: Ghidra fetcher (download + verify + slim)
# ==============================================================
FROM python:${PYTHON_VERSION}-slim-bookworm AS ghidra-fetcher

ARG GHIDRA_VERSION
ARG GHIDRA_DATE
ARG GHIDRA_SHA256

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    unzip \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fSL -o /tmp/ghidra.zip \
      "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_DATE}.zip" \
    && echo "${GHIDRA_SHA256}  /tmp/ghidra.zip" | sha256sum -c - \
    && unzip -q /tmp/ghidra.zip -d /opt \
    && mv /opt/ghidra_${GHIDRA_VERSION}_PUBLIC /opt/ghidra \
    && rm /tmp/ghidra.zip \
    # Slim down: remove docs, extensions, licenses (~200MB savings)
    && rm -rf /opt/ghidra/docs \
              /opt/ghidra/Extensions \
              /opt/ghidra/licenses \
              /opt/ghidra/Ghidra/Features/*/data/doc

# ==============================================================
# Stage 4: Base runtime (shared by all targets)
# ==============================================================
FROM python:${PYTHON_VERSION}-slim-bookworm AS base-runtime

# Non-root user
RUN groupadd -r reversetool && useradd -r -g reversetool -m reversetool

# Python deps from builder
COPY --from=python-builder /opt/python-deps /usr/local

# Entrypoint
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# OCI labels
LABEL org.opencontainers.image.title="ReverseTool" \
      org.opencontainers.image.description="Binary analysis feature extraction framework" \
      org.opencontainers.image.source="https://github.com/bolin8017/ReverseTool" \
      org.opencontainers.image.vendor="PolinLai" \
      org.opencontainers.image.licenses="MIT"

ENTRYPOINT ["entrypoint.sh"]
CMD ["--help"]

# ==============================================================
# Target: radare2-only (~200MB)
# ==============================================================
FROM base-runtime AS radare2-only

# Runtime libs for radare2
RUN apt-get update && apt-get install -y --no-install-recommends \
    libzip4 \
    && rm -rf /var/lib/apt/lists/*

# Radare2 binaries + libs
COPY --from=radare2-builder /opt/radare2 /opt/radare2
ENV PATH="/opt/radare2/bin:${PATH}" \
    LD_LIBRARY_PATH="/opt/radare2/lib"

# Install r2pipe
RUN pip install --no-cache-dir r2pipe==1.9.8

USER reversetool
WORKDIR /data

# ==============================================================
# Target: ghidra-only (~750MB)
# ==============================================================
FROM base-runtime AS ghidra-only

# JRE 21 from Temurin (not full JDK — saves ~150MB)
COPY --from=eclipse-temurin:21-jre-jammy /opt/java/openjdk /opt/java/openjdk
ENV JAVA_HOME="/opt/java/openjdk" \
    PATH="/opt/java/openjdk/bin:${PATH}"

# Ghidra installation
COPY --from=ghidra-fetcher /opt/ghidra /opt/ghidra
ENV GHIDRA_INSTALL_DIR="/opt/ghidra" \
    PATH="/opt/ghidra/support:${PATH}"

USER reversetool
WORKDIR /data

# ==============================================================
# Target: full (Ghidra + Radare2, ~900MB) — DEFAULT
# ==============================================================
FROM base-runtime AS full

# Runtime libs for radare2
RUN apt-get update && apt-get install -y --no-install-recommends \
    libzip4 \
    && rm -rf /var/lib/apt/lists/*

# Radare2
COPY --from=radare2-builder /opt/radare2 /opt/radare2

# JRE 21
COPY --from=eclipse-temurin:21-jre-jammy /opt/java/openjdk /opt/java/openjdk

# Ghidra
COPY --from=ghidra-fetcher /opt/ghidra /opt/ghidra

ENV PATH="/opt/radare2/bin:/opt/java/openjdk/bin:/opt/ghidra/support:${PATH}" \
    LD_LIBRARY_PATH="/opt/radare2/lib" \
    JAVA_HOME="/opt/java/openjdk" \
    GHIDRA_INSTALL_DIR="/opt/ghidra"

# Install r2pipe
RUN pip install --no-cache-dir r2pipe==1.9.8

USER reversetool
WORKDIR /data
```

- [ ] **Step 2: Write docker-compose.dev.yml**

`docker/docker-compose.dev.yml`:
```yaml
# Development convenience — mount local samples and output
# Usage: docker compose -f docker/docker-compose.dev.yml run reverse-tool opcode -b radare2 -d /data
services:
  reverse-tool:
    build:
      context: ..
      dockerfile: docker/Dockerfile
      target: full
    volumes:
      - ../samples:/data:ro
      - ../output:/output
```

- [ ] **Step 3: Commit**

```bash
git add docker/Dockerfile docker/docker-compose.dev.yml
git commit -m "feat: add multi-stage multi-target Dockerfile"
```

---

### Task 3: Build and Verify Radare2-Only Image

This is the lightest image and fastest to build. Good for initial validation.

- [ ] **Step 1: Build radare2-only image**

```bash
docker build --target radare2-only -t reverse-tool:radare2-test -f docker/Dockerfile .
```

- [ ] **Step 2: Verify**

```bash
# CLI works
docker run --rm reverse-tool:radare2-test --version
docker run --rm reverse-tool:radare2-test doctor
docker run --rm reverse-tool:radare2-test backends

# r2 is available
docker run --rm reverse-tool:radare2-test r2 -v

# Non-root user
docker run --rm reverse-tool:radare2-test bash -c "whoami"
# Expected: reversetool
```

- [ ] **Step 3: Check image size**

```bash
docker images reverse-tool:radare2-test --format "{{.Size}}"
```
Expected: ~200-300MB

- [ ] **Step 4: Commit build verification notes**

```bash
git add -A
git commit -m "chore: verify radare2-only Docker image builds and runs"
```

---

### Task 4: Build Full Image

- [ ] **Step 1: Build full image**

```bash
docker build --target full -t reverse-tool:full-test -f docker/Dockerfile .
```
Note: This takes longer (~10-15 min) due to Ghidra download + Radare2 compilation.

- [ ] **Step 2: Verify**

```bash
docker run --rm reverse-tool:full-test --version
docker run --rm reverse-tool:full-test doctor
docker run --rm reverse-tool:full-test backends
docker run --rm reverse-tool:full-test r2 -v
docker run --rm reverse-tool:full-test java -version
docker run --rm reverse-tool:full-test bash -c "whoami"
```

- [ ] **Step 3: Check image sizes**

```bash
docker images reverse-tool --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}"
```

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "chore: phase 3 Docker images complete"
```
