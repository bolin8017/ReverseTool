# Docker Guide

ReverseTool provides Docker images with all analysis tools pre-installed. This is the recommended way to use ReverseTool -- no need to install Ghidra, Radare2, or manage dependencies.

## Image Variants

| Target | Suggested Tag | Size | Contents |
|--------|---------------|------|----------|
| `full` | `reverse-tool:latest` | ~1.08 GB | Ghidra 12.0.4 + Radare2 6.1.2 |
| `ghidra-only` | `reverse-tool:ghidra` | ~1.02 GB | Ghidra 12.0.4 only |
| `radare2-only` | `reverse-tool:radare2` | ~200 MB | Radare2 6.1.2 only |

All images are based on `python:3.12-slim-bookworm` and run as a non-root user (`reversetool`).

## Building Images

```bash
# Full image (Ghidra + Radare2) -- default
docker build --target full -t reverse-tool:latest -f docker/Dockerfile .

# Ghidra only
docker build --target ghidra-only -t reverse-tool:ghidra -f docker/Dockerfile .

# Radare2 only (smallest image)
docker build --target radare2-only -t reverse-tool:radare2 -f docker/Dockerfile .
```

### Build Architecture

The Dockerfile uses multi-stage builds:

1. **python-builder** -- Installs Python dependencies from `pyproject.toml`
2. **radare2-builder** -- Compiles Radare2 6.1.2 from source with Meson/Ninja
3. **ghidra-fetcher** -- Downloads and verifies Ghidra 12.0.4 (SHA-256 checked)
4. **base-runtime** -- Shared runtime base with Python deps and non-root user
5. **Target stages** -- Combine base-runtime with the appropriate backends

## Basic Usage

```bash
docker run --rm --user $(id -u):$(id -g) \
  -v /path/to/binaries:/data:ro \
  -v /path/to/output:/output \
  reverse-tool opcode -b radare2 -d /data -o /output
```

Key flags:
- `--rm` -- Remove container after exit
- `--user $(id -u):$(id -g)` -- Match host user to avoid permission issues
- `-v /path:/data:ro` -- Mount input directory as read-only
- `-v /path:/output` -- Mount output directory as read-write

### Examples

```bash
# Opcode extraction with Radare2
docker run --rm --user $(id -u):$(id -g) \
  -v ~/samples:/data:ro -v ~/results:/output \
  reverse-tool opcode -b radare2 -d /data -o /output

# Function call extraction with Ghidra
docker run --rm --user $(id -u):$(id -g) \
  -v ~/samples:/data:ro -v ~/results:/output \
  reverse-tool function-call -b ghidra -d /data -o /output

# Environment check
docker run --rm reverse-tool doctor

# Show version
docker run --rm reverse-tool --version
```

## Wrapper Script

The wrapper script `scripts/reverse-tool-docker` makes Docker usage feel identical to native installation.

### Installation

```bash
# System-wide
sudo cp scripts/reverse-tool-docker /usr/local/bin/

# User-local
cp scripts/reverse-tool-docker ~/.local/bin/
```

### Usage

```bash
# These work exactly like native commands:
reverse-tool-docker opcode -b radare2 -d /path/to/binaries -o /path/to/output
reverse-tool-docker function-call -b ghidra -d /path/to/binaries -o /path/to/output
reverse-tool-docker doctor
```

The wrapper automatically:
- Translates host paths to container paths
- Mounts input directory as read-only (`/data`)
- Mounts output directory as read-write (`/output`)
- Maps the host user ID to avoid permission issues
- Creates the output directory if it does not exist

### Configuration

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `REVERSE_TOOL_IMAGE` | `reverse-tool` | Docker image name/tag to use |
| `REVERSE_TOOL_BACKEND` | (none) | Default backend if `-b` not specified |

Example:

```bash
# Use the radare2-only image
REVERSE_TOOL_IMAGE=reverse-tool:radare2 reverse-tool-docker opcode -b radare2 -d ./samples -o ./output
```

## Interactive Debugging

To inspect the container environment or debug issues:

```bash
# Open a bash shell inside the full image
docker run -it --entrypoint bash reverse-tool:latest

# Check Radare2 version directly
docker run --rm reverse-tool:latest r2 -v

# Check Ghidra version
docker run --rm reverse-tool:latest analyzeHeadless --version

# Run with debug output
docker run --rm --user $(id -u):$(id -g) \
  -v ~/samples:/data:ro -v ~/results:/output \
  reverse-tool -vv opcode -b radare2 -d /data -o /output
```

## Custom Image Building

### Pinned Versions

The Dockerfile uses build arguments for version pinning:

| Argument | Default | Description |
|----------|---------|-------------|
| `PYTHON_VERSION` | `3.12` | Python base image version |
| `RADARE2_VERSION` | `6.1.2` | Radare2 Git tag |
| `GHIDRA_VERSION` | `12.0.4` | Ghidra release version |
| `GHIDRA_DATE` | `20260303` | Ghidra release date suffix |
| `GHIDRA_SHA256` | (pinned) | SHA-256 checksum of Ghidra ZIP |

### Building with Custom Versions

```bash
# Use a different Radare2 version
docker build --target full \
  --build-arg RADARE2_VERSION=6.2.0 \
  -t reverse-tool:custom -f docker/Dockerfile .
```

> **Note**: Changing Ghidra version requires updating both `GHIDRA_VERSION`, `GHIDRA_DATE`, and `GHIDRA_SHA256` to match the official release.

## Volume Mount Patterns

### Read-Only Input

Always mount input binaries as read-only to prevent accidental modification:

```bash
-v /path/to/binaries:/data:ro
```

### Persistent Output

Mount a host directory for output to persist results after the container exits:

```bash
-v /path/to/output:/output
```

### Batch Processing Script

```bash
#!/bin/bash
# Process multiple directories
for dir in /samples/family_*; do
  name=$(basename "$dir")
  docker run --rm --user $(id -u):$(id -g) \
    -v "$dir":/data:ro \
    -v "/results/$name":/output \
    reverse-tool opcode -b radare2 -d /data -o /output
done
```
