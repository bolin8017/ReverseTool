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
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir setuptools

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
ENV LD_LIBRARY_PATH="/opt/radare2/lib/x86_64-linux-gnu:/opt/radare2/lib"
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
    LD_LIBRARY_PATH="/opt/radare2/lib/x86_64-linux-gnu:/opt/radare2/lib"

# Install r2pipe (no pyghidra — this image has no Ghidra/JDK)
RUN pip install --no-cache-dir r2pipe==1.9.8

USER reversetool
WORKDIR /data

# ==============================================================
# Target: ghidra-only (~750MB)
# ==============================================================
FROM base-runtime AS ghidra-only

# JDK 21 from Temurin (Ghidra 12.0.4 requires full JDK, not just JRE)
COPY --from=eclipse-temurin:21-jdk-jammy /opt/java/openjdk /opt/java/openjdk
ENV JAVA_HOME="/opt/java/openjdk" \
    PATH="/opt/java/openjdk/bin:${PATH}"

# Ghidra installation
COPY --from=ghidra-fetcher /opt/ghidra /opt/ghidra
ENV GHIDRA_INSTALL_DIR="/opt/ghidra" \
    PATH="/opt/ghidra/support:${PATH}"

# PyGhidra bridge (required for Python scripting in Ghidra 12.0.4+)
RUN pip install --no-cache-dir pyghidra==3.0.2

USER reversetool
WORKDIR /data

# ==============================================================
# Target: full (Ghidra + Radare2, ~1.1GB) — DEFAULT
# ==============================================================
FROM base-runtime AS full

# Runtime libs for radare2
RUN apt-get update && apt-get install -y --no-install-recommends \
    libzip4 \
    && rm -rf /var/lib/apt/lists/*

# Radare2
COPY --from=radare2-builder /opt/radare2 /opt/radare2

# JDK 21 (Ghidra 12.0.4 requires full JDK)
COPY --from=eclipse-temurin:21-jdk-jammy /opt/java/openjdk /opt/java/openjdk

# Ghidra
COPY --from=ghidra-fetcher /opt/ghidra /opt/ghidra

ENV PATH="/opt/radare2/bin:/opt/java/openjdk/bin:/opt/ghidra/support:${PATH}" \
    LD_LIBRARY_PATH="/opt/radare2/lib/x86_64-linux-gnu:/opt/radare2/lib" \
    JAVA_HOME="/opt/java/openjdk" \
    GHIDRA_INSTALL_DIR="/opt/ghidra"

# Install r2pipe
RUN pip install --no-cache-dir r2pipe==1.9.8 pyghidra==3.0.2

USER reversetool
WORKDIR /data
