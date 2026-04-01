# ReverseTool

[![CI](https://github.com/bolin8017/ReverseTool/actions/workflows/ci.yml/badge.svg)](https://github.com/bolin8017/ReverseTool/actions/workflows/ci.yml)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> Binary analysis feature extraction framework powered by Ghidra, Radare2, and IDA Pro.

ReverseTool extracts structured features from binary files for malware classification, similarity analysis, and threat hunting. It provides a unified CLI and Python API across multiple reverse engineering backends.

## Highlights

- **Multi-backend** -- Unified interface for Ghidra 12.0.4, Radare2 6.1.2, and IDA Pro 9.3+
- **Pluggable extractors** -- Auto-discovered plugin architecture; add new extractors in ~50 lines
- **Docker-first** -- Pre-configured images with all tools included; zero setup
- **Parallel processing** -- Batch-analyze thousands of binaries with ProcessPoolExecutor

## Quick Start

### Docker (recommended)

```bash
git clone https://github.com/bolin8017/ReverseTool.git && cd ReverseTool
docker build --target full -t reverse-tool -f docker/Dockerfile .
docker run --rm --user $(id -u):$(id -g) \
  -v /path/to/binaries:/data:ro \
  -v /path/to/output:/output \
  reverse-tool opcode -b radare2 -d /data -o /output
```

See [docs/docker.md](docs/docker.md) for image variants, wrapper script, and advanced usage.

### Native Install

```bash
git clone https://github.com/bolin8017/ReverseTool.git && cd ReverseTool
./install.sh                    # Python 3.12 + Radare2 + ReverseTool
./install.sh --with-ghidra      # + Ghidra 12.0.4 + JDK 21
source .venv/bin/activate
```

### IDA Pro

```bash
reverse-tool opcode -b idapro -d /path/to/binaries -i /path/to/idapro/idat
```

Or configure in `~/.config/reverse-tool/config.toml` -- see [docs/installation.md](docs/installation.md).

### pip (from source)

```bash
git clone https://github.com/bolin8017/ReverseTool.git && cd ReverseTool
pip install -e ".[radare2]"    # r2pipe (requires r2 on PATH)
pip install -e ".[ghidra]"     # pyghidra (requires Ghidra installed)
```

## Usage

### Opcode Extraction

Extracts opcode mnemonics from all sections. Output: JSONL.

```bash
reverse-tool opcode -b radare2 -d /path/to/binaries
reverse-tool opcode -b ghidra  -d /path/to/binaries -g ~/ghidra/support/analyzeHeadless
reverse-tool opcode -b idapro  -d /path/to/binaries -i /path/to/idat
```

See [docs/output-formats.md](docs/output-formats.md) for full schema and field descriptions.

### Function Call Extraction

Extracts function call graphs with per-function disassembly. Output: JSON.

```bash
reverse-tool function-call -b radare2 -d /path/to/binaries
reverse-tool function-call -b ghidra  -d /path/to/binaries -g ~/ghidra/support/analyzeHeadless
reverse-tool function-call -b idapro  -d /path/to/binaries -i /path/to/idat
```

See [docs/output-formats.md](docs/output-formats.md) for call graph schema and DOT output.

### Environment Check

```bash
reverse-tool doctor
```

```
ReverseTool v1.0.0
Python:   3.12.11
Platform: Linux-5.15.0-x86_64
Ghidra:   12.0.4 (/opt/ghidra/support/analyzeHeadless)
Radare2:  6.1.2 (/opt/radare2/bin/r2)
IDA Pro:  9.3 (/opt/idapro/idat)
Extractors: 2 registered
  - function_call
  - opcode
```

## Architecture

```
reverse-tool <extractor> -b <backend> -d <directory>
       |
       v
+-------------+     +----------------+     +---------------+
|     CLI     |---->|     Engine     |---->|    Backend    |
|   (Click)   |     |  (Parallel)    |     |  (Ghidra/r2/  |
|             |     |                |     |    IDA Pro)   |
+-------------+     +-------+--------+     +-------+-------+
                            |                      |
                            v                      v
                    +----------------+     +----------------+
                    |   Extractor    |<----|    Session     |
                    |  (opcode/fc)   |     | (ctx manager)  |
                    +-------+--------+     +----------------+
                            |
                            v
                    +----------------+
                    |     Writer     |
                    | (JSONL/JSON/   |
                    |     DOT)       |
                    +----------------+
```

- **Extractor-centric** -- Organized by what you extract, not which tool you use
- **Auto-discovery** -- New extractors auto-register via `__init_subclass__`
- **Context manager sessions** -- Backend sessions are always properly cleaned up
- **Generic typing** -- `BaseBackend[T_Session]` provides type-safe session handles

## Documentation

| Document | Description |
|----------|-------------|
| [Installation Guide](docs/installation.md) | All install methods, configuration, comparison table |
| [Output Formats](docs/output-formats.md) | JSONL/JSON schemas, field reference, directory structure |
| [Backend Details](docs/backends.md) | Ghidra / Radare2 / IDA Pro internals and comparison |
| [Custom Extractors](docs/custom-extractors.md) | Tutorial for adding new extractors |
| [Docker Guide](docs/docker.md) | Image variants, wrapper script, advanced usage |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, coding standards, and the guide to adding new extractors.

## License

[MIT](LICENSE)

## Citation

If you use ReverseTool in academic research, please cite:

```bibtex
@software{reversetool,
  title = {ReverseTool: Binary Analysis Feature Extraction Framework},
  author = {PolinLai},
  url = {https://github.com/bolin8017/ReverseTool},
  version = {1.0.0},
  license = {MIT},
  year = {2026}
}
```
