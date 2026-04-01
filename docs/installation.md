# Installation Guide

ReverseTool supports four installation methods. Choose the one that fits your workflow.

## Comparison

| | Docker | Native (install.sh) | pip install | IDA Pro |
|---|---|---|---|---|
| Ghidra + Radare2 included | Yes | Yes | No | No |
| Needs sudo | Only for Docker itself | Only for gcc/git | No | No |
| System pollution | None (container) | None (~/.local/) | Depends | N/A |
| CLI command | `reverse-tool-docker` | `reverse-tool` | `reverse-tool` | `reverse-tool` |
| Best for | Most users | Daily research | Existing environments | Commercial license holders |

## Option 1: Docker (Recommended)

Pre-configured images with Ghidra, Radare2, and all dependencies. Nothing else to install.

### Build the Image

```bash
git clone https://github.com/bolin8017/ReverseTool.git
cd ReverseTool
docker build --target full -t reverse-tool -f docker/Dockerfile .
```

Three image targets are available:

| Target | Tag | Size | Contents |
|--------|-----|------|----------|
| `full` | `reverse-tool:latest` | ~1.08 GB | Ghidra 12.0.4 + Radare2 6.1.2 |
| `ghidra-only` | `reverse-tool:ghidra` | ~1.02 GB | Ghidra 12.0.4 only |
| `radare2-only` | `reverse-tool:radare2` | ~200 MB | Radare2 6.1.2 only |

```bash
docker build --target radare2-only -t reverse-tool:radare2 -f docker/Dockerfile .
docker build --target ghidra-only  -t reverse-tool:ghidra  -f docker/Dockerfile .
```

### Run

```bash
docker run --rm --user $(id -u):$(id -g) \
  -v /path/to/binaries:/data:ro \
  -v /path/to/output:/output \
  reverse-tool opcode -b radare2 -d /data -o /output
```

### Wrapper Script

To avoid typing the long `docker run` command, install the wrapper script:

```bash
sudo cp scripts/reverse-tool-docker /usr/local/bin/
# or without sudo:
cp scripts/reverse-tool-docker ~/.local/bin/

# Now use it like a native command:
reverse-tool-docker opcode -b radare2 -d /path/to/binaries -o /path/to/output
reverse-tool-docker function-call -b ghidra -d /path/to/binaries -o /path/to/output
reverse-tool-docker doctor
```

The wrapper automatically handles volume mounting, user ID mapping, and path translation.

Environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `REVERSE_TOOL_IMAGE` | `reverse-tool` | Docker image to use |
| `REVERSE_TOOL_BACKEND` | (none) | Default backend if `-b` not specified |

See [docs/docker.md](docker.md) for advanced Docker usage.

## Option 2: Native Install (install.sh)

Installs Python 3.12, Radare2, and ReverseTool under `~/.local/` with no system pollution.

```bash
git clone https://github.com/bolin8017/ReverseTool.git
cd ReverseTool
./install.sh                    # Python 3.12 + Radare2 + ReverseTool
./install.sh --with-ghidra      # + Ghidra 12.0.4 + JDK 21

# Activate and use
source .venv/bin/activate
reverse-tool opcode -b radare2 -d /path/to/binaries -o ./output
```

The script:
- Installs Python 3.12 via pyenv (if not already available)
- Compiles Radare2 6.1.2 from source under `~/.local/`
- Creates a virtualenv and installs ReverseTool with all dependencies
- Optionally downloads Ghidra 12.0.4 and JDK 21

## Option 3: IDA Pro Backend (Local-Only)

IDA Pro is commercial software and cannot be bundled. To use the IDA Pro backend:

1. Install IDA Pro 9.3+ on your system
2. Provide the path to `idat` via `--ida-path` or add it to your PATH

```bash
# With explicit path
reverse-tool opcode -b idapro -d /path/to/binaries \
  -i /path/to/idapro/idat

# Or add to PATH
echo 'export PATH="/path/to/idapro:$PATH"' >> ~/.bashrc
```

Or configure in `~/.config/reverse-tool/config.toml`:

```toml
[backends.idapro]
path = "/path/to/idapro/idat"
```

## Option 4: pip Install from Source (Advanced)

For users who manage backends themselves. You must have the backend tools already installed and on your PATH.

```bash
git clone https://github.com/bolin8017/ReverseTool.git && cd ReverseTool
pip install -e ".[radare2]"    # Adds r2pipe (requires r2 on PATH)
pip install -e ".[ghidra]"     # Adds pyghidra (requires Ghidra installed)
```

## Configuration

ReverseTool uses an optional TOML config file at `~/.config/reverse-tool/config.toml`.

Priority order: **CLI flags > environment variables > config file > defaults**.

### Full Configuration Reference

```toml
[defaults]
backend = "ghidra"          # Default backend when -b is omitted
timeout = 600               # Per-file timeout in seconds (default: 600)
max_workers = 4             # Parallel workers (default: CPU count)

[backends.ghidra]
path = "/opt/ghidra_12.0.4/support/analyzeHeadless"

[backends.radare2]
analysis_level = "aa"       # Radare2 analysis depth (default: "aa")
                            # Options: "a" (basic), "aa" (standard), "aaa" (deep)

[backends.idapro]
path = "/opt/idapro/idat"
```

### Configuration Fields

| Section | Key | Type | Default | Description |
|---------|-----|------|---------|-------------|
| `defaults` | `backend` | string | (none) | Default analysis backend |
| `defaults` | `timeout` | int | 600 | Per-file analysis timeout in seconds |
| `defaults` | `max_workers` | int | CPU count | Number of parallel workers |
| `backends.ghidra` | `path` | string | (auto-detect) | Path to `analyzeHeadless` |
| `backends.radare2` | `analysis_level` | string | `"aa"` | Radare2 analysis depth |
| `backends.idapro` | `path` | string | (auto-detect) | Path to `idat` binary |
