# ReverseTool Unified Design Spec

**Date:** 2026-04-01
**Status:** Approved
**Authors:** PolinLai, Claude (design assistance)

---

## 1. Overview

### Problem Statement

Two existing projects — **OpCodeReverseTool** (opcode extraction) and
**FunctionCallReverseTool** (function call graph extraction) — share nearly
identical architecture (backend ABC, parallel processing, CLI) but live in
separate repositories. This duplication creates maintenance burden and
prevents a unified user experience.

### Solution

Merge both projects into **ReverseTool**, a unified binary analysis feature
extraction framework with:

- A shared core (engine, backends, CLI)
- An extractor-centric plugin architecture (auto-discovered)
- Docker-first deployment with pip install as secondary
- Production-grade CI/CD, testing, and documentation

### Target Users

- Security researchers extracting features for ML-based malware classification
- Reverse engineers using feature extraction as part of daily analysis workflows

### Non-Goals

- CI/CD pipeline integration (API server, event-driven)
- Real-time analysis or interactive disassembly
- Replacing Ghidra/Radare2 as general-purpose RE tools

---

## 2. Version-Locked Dependencies

| Component | Version | EOL / Support |
|-----------|---------|---------------|
| Python | 3.12 | 2028-10 |
| Ghidra | 12.0.4 | Uses PyGhidra (native CPython 3), not Jython |
| Java | JRE 21 (Temurin) | JRE only, not full JDK |
| Radare2 | 6.1.2 | Compiled from git tag |
| r2pipe | 1.9.8 | PyPI |
| Docker base | python:3.12-slim-bookworm | Debian 12 based |

---

## 3. Package Structure

Uses **src layout** (PyPA recommended).

```
ReverseTool/
├── src/
│   └── reverse_tool/
│       ├── __init__.py              # Public API + __version__
│       ├── __main__.py              # python -m reverse_tool
│       ├── py.typed                 # PEP 561 type marker
│       ├── _typing.py              # Internal type aliases (T_Session, etc.)
│       ├── cli.py                  # Click CLI + ExtractorGroup auto-discovery
│       ├── engine.py               # Parallel orchestration + ProgressCallback
│       ├── discovery.py            # __init_subclass__ + pkgutil scanning
│       ├── exceptions.py           # Structured exception hierarchy
│       ├── config.py               # TOML config loading
│       │
│       ├── backends/
│       │   ├── __init__.py         # Re-export BaseBackend, get_backend()
│       │   ├── _base.py            # BaseBackend(ABC, Generic[T_Session])
│       │   ├── ghidra.py           # GhidraBackend
│       │   ├── radare2.py          # Radare2Backend
│       │   └── null.py             # NullBackend (programmable, for testing)
│       │
│       └── extractors/
│           ├── __init__.py         # Re-export BaseExtractor
│           ├── _base.py            # BaseExtractor ABC
│           ├── opcode/
│           │   ├── __init__.py     # OpcodeExtractor registration + metadata
│           │   ├── _models.py      # OpcodeRow, OpcodeResult
│           │   ├── _ghidra.py      # Ghidra opcode extraction logic
│           │   ├── _radare2.py     # Radare2 opcode extraction logic
│           │   ├── _writer.py      # CSV output
│           │   └── _scripts/
│           │       └── ghidra_opcode.py  # Ghidra postscript (PyGhidra)
│           └── function_call/
│               ├── __init__.py
│               ├── _models.py      # FunctionNode, CallGraph
│               ├── _ghidra.py
│               ├── _radare2.py
│               ├── _writer.py      # DOT + JSON output
│               └── _scripts/
│                   └── ghidra_function_call.py
│
├── tests/
│   ├── conftest.py                 # NullBackend fixtures, backend detection, markers
│   ├── binary_factory.py           # On-the-fly test binary generation
│   ├── unit/                       # ~75% — no external tool dependencies
│   │   ├── test_engine.py
│   │   ├── test_discovery.py
│   │   ├── test_config.py
│   │   ├── writers/
│   │   │   ├── test_csv_writer.py
│   │   │   ├── test_dot_writer.py
│   │   │   ├── test_json_writer.py
│   │   │   └── test_writers_property.py  # Hypothesis
│   │   └── extractors/
│   │       ├── test_opcode.py      # Against NullBackend
│   │       └── test_function_call.py
│   ├── integration/                # ~20% — requires real backend (Docker)
│   │   ├── radare2/
│   │   └── ghidra/
│   ├── cross_backend/              # ~5% — requires both backends
│   │   └── test_consistency.py
│   └── docker/
│       ├── test_docker_images.py
│       └── container-structure-test.yaml
│
├── docker/
│   └── Dockerfile                  # Single file, multi-target (full/ghidra/radare2)
│
├── docs/                           # MkDocs Material
│   ├── index.md
│   ├── getting-started/
│   ├── user-guide/
│   ├── extractors/
│   ├── development/
│   │   ├── architecture.md
│   │   ├── adding-extractors.md
│   │   └── adrs/
│   └── superpowers/specs/          # Design specs (this file)
│
├── .github/
│   ├── workflows/
│   │   ├── ci.yml                  # lint → unit-test → build-docker → integration → scan
│   │   ├── release.yml             # tag → PyPI (OIDC) + Docker + GitHub Release
│   │   └── pip-audit.yml           # Weekly dependency vulnerability scan
│   ├── ISSUE_TEMPLATE/
│   │   ├── bug_report.yml
│   │   ├── feature_request.yml
│   │   ├── extractor_proposal.yml
│   │   └── config.yml
│   ├── PULL_REQUEST_TEMPLATE.md
│   ├── dependabot.yml
│   └── CODEOWNERS
│
├── justfile                        # Task runner (setup, lint, test, docker-build)
├── pyproject.toml                  # Loose deps + optional groups [ghidra], [radare2], [dev]
├── requirements.txt                # Pinned exact versions for reproducibility
├── mkdocs.yml
├── CONTRIBUTING.md
├── CHANGELOG.md
├── SECURITY.md
├── CITATION.cff
├── CODE_OF_CONDUCT.md              # Contributor Covenant v2.1
└── LICENSE                         # MIT
```

---

## 4. Core Abstractions

### 4.1 BaseBackend

Manages reverse engineering tool lifecycle. Thin wrapper — does NOT contain
extraction logic.

```python
from __future__ import annotations
from abc import ABC, abstractmethod
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Generic, TypeVar, Iterator

T_Session = TypeVar("T_Session")

@dataclass(frozen=True)
class BackendInfo:
    name: str
    version: str

class BaseBackend(ABC, Generic[T_Session]):

    @property
    @abstractmethod
    def info(self) -> BackendInfo: ...

    @abstractmethod
    def validate_environment(self) -> None: ...

    @abstractmethod
    def _open_session(self, input_file: Path, timeout: int) -> T_Session: ...

    @abstractmethod
    def _close_session(self, session: T_Session) -> None: ...

    @contextmanager
    def session(self, input_file: Path, timeout: int = 600) -> Iterator[T_Session]:
        s = self._open_session(input_file, timeout)
        try:
            yield s
        finally:
            self._close_session(s)
```

**Design decisions:**
- `Generic[T_Session]` — typed session handles, no `Any`
- Context manager as the ONLY public session API — prevents resource leaks
- `_open_session` / `_close_session` are private (underscore) — subclasses
  implement them, callers use `session()`
- `BackendInfo` dataclass separates metadata from behavior

### 4.2 BaseExtractor

Defines a specific feature extraction capability.

```python
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Generic
import logging

@dataclass(frozen=True)
class ExtractResult:
    extractor_name: str
    input_file: Path
    data: dict
    metadata: dict = field(default_factory=dict)

class BaseExtractor(ABC, Generic[T_Session]):

    @property
    @abstractmethod
    def name(self) -> str: ...

    @property
    @abstractmethod
    def description(self) -> str: ...

    @property
    @abstractmethod
    def supported_backends(self) -> frozenset[str]: ...

    @abstractmethod
    def extract(
        self, session: T_Session, input_file: Path, logger: logging.Logger
    ) -> ExtractResult: ...

    @abstractmethod
    def write_output(self, result: ExtractResult, output_dir: Path) -> list[Path]: ...

    def supports_backend(self, backend: BaseBackend) -> bool:
        return backend.info.name in self.supported_backends

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        import inspect
        if not inspect.isabstract(cls):
            from reverse_tool.discovery import _register_extractor
            _register_extractor(cls)
```

**Design decisions:**
- `supported_backends` is `frozenset` — set-membership semantics
- `write_output` returns `list[Path]` — callers know what was created
- `__init_subclass__` auto-registers concrete subclasses — zero boilerplate
- Properties with `@abstractmethod` — prevents subclasses from forgetting

### 4.3 Execution Flow

```
CLI parses args (Click + ExtractorGroup)
  ↓
engine.process_files(files, backend_cls, extractor_cls)
  ↓
ProcessPoolExecutor (passes CLASSES, not instances):
  ↓ per worker process:
  ├─ backend = backend_cls()
  ├─ extractor = extractor_cls()
  ├─ backend.validate_environment()
  ├─ with backend.session(file, timeout) as session:
  │    ├─ extractor.extract(session, file, logger) → ExtractResult
  │    └─ extractor.write_output(result, output_dir) → [Path]
  └─ return TaskResult(success=True, output_files=[...])
```

Key: classes are picklable, instances with open sessions are not.

---

## 5. Auto-Discovery

Uses `__init_subclass__` (implicit registration) + `pkgutil.walk_packages`
(explicit scanning).

```python
# discovery.py
_EXTRACTOR_REGISTRY: dict[str, type[BaseExtractor]] = {}

def discover_extractors() -> dict[str, type[BaseExtractor]]:
    import reverse_tool.extractors as ext_pkg
    for finder, module_name, is_pkg in pkgutil.walk_packages(
        ext_pkg.__path__, prefix=ext_pkg.__name__ + "."
    ):
        try:
            importlib.import_module(module_name)
        except ImportError as e:
            logger.warning("Skipping %s: %s", module_name, e)
    return dict(_EXTRACTOR_REGISTRY)
```

Adding a new extractor requires:
1. Create directory under `extractors/`
2. Implement `BaseExtractor` subclass
3. Done — auto-discovered, auto-registered, auto-appears in CLI

---

## 6. CLI Design

Framework: **Click** with `rich-click` for formatted help.

```
reverse-tool
├── --version                     # Tool + backend versions with -v
├── -v / --verbose                # Stackable (-v, -vv, -vvv)
├── --json                        # JSON output mode
├── -q / --quiet                  # Suppress progress, output paths only
├── --config PATH                 # Override config file
│
├── opcode                        # [auto-discovered subcommand]
│   ├── -b / --backend            #   Required: ghidra | radare2
│   ├── -d / --directory          #   Required: input directory
│   ├── -g / --ghidra-path        #   Conditional (ghidra backend only)
│   ├── -o / --output             #   Output dir (default: ./output)
│   ├── -t / --timeout            #   Per-file timeout seconds (default: 600)
│   └── --pattern                 #   Glob pattern for file filtering
│
├── function-call                 # [auto-discovered subcommand]
│   └── (same options structure)
│
├── backends                      # List available backends + status
├── doctor                        # Full environment health check
└── config                        # Config management
    ├── show                      # Display effective config
    ├── path                      # Print config file location
    └── set KEY VALUE             # Set a config value
```

### Error Messages

Three-part format (What + Why + Fix), inspired by Rust toolchain:

```
Error: Ghidra not found at /opt/ghidra/support/analyzeHeadless
Cause: The --ghidra-path does not point to a valid executable
Fix:   Install Ghidra or use Docker: docker run reverse-tool opcode -b ghidra -d /data
```

### Exit Codes

```python
SUCCESS = 0
GENERAL_ERROR = 1
USAGE_ERROR = 2
BACKEND_NOT_FOUND = 10
PARTIAL_FAILURE = 11    # Some files failed in batch (not 0, not 1)
TIMEOUT = 12
CONFIG_ERROR = 20
```

### Configuration

TOML format at `~/.config/reverse-tool/config.toml`:

```toml
[defaults]
backend = "ghidra"
timeout = 600

[backends.ghidra]
path = "/opt/ghidra_12.0.4/support/analyzeHeadless"

[backends.radare2]
analysis_level = "aa"
```

Priority: CLI flags > env vars > config file > defaults.

---

## 7. Exception Hierarchy

```python
class ReverseToolError(Exception): ...

class BackendError(ReverseToolError): ...
class BackendNotAvailable(BackendError): ...
class BackendVersionError(BackendError): ...
class BackendTimeout(BackendError): ...

class ExtractionError(ReverseToolError): ...
class IncompatibleBackendError(ExtractionError): ...

class OutputWriteError(ReverseToolError): ...
class ConfigError(ReverseToolError): ...
```

---

## 8. Engine Design

### Parallel Processing

```python
def process_files(
    files: list[Path],
    backend_cls: type[BaseBackend],
    extractor_cls: type[BaseExtractor],
    output_dir: Path,
    *,
    max_workers: int | None = None,
    timeout: int = 600,
    progress: ProgressCallback | None = None,
) -> Iterator[TaskResult]:
```

Key features:
- **Pass classes, not instances** to workers (picklable)
- **ProcessPoolExecutor** (CPU-bound disassembly, process isolation)
- **max_workers=1 uses sequential path** for debugging
- **ProgressCallback Protocol** decouples engine from UI
- **Idempotent skip logic** — checks `.complete` marker file, skips if output
  is newer than input

### ProgressCallback Protocol

```python
class ProgressCallback(Protocol):
    def on_start(self, total_files: int) -> None: ...
    def on_file_complete(self, result: TaskResult) -> None: ...
    def on_finish(self, results: list[TaskResult]) -> None: ...
```

CLI layer injects `RichProgress` implementation when tty is detected.

---

## 9. Docker Strategy

### Single Dockerfile, Multi-Target

```
docker/
└── Dockerfile        # Stages: builder, ghidra-fetcher, base-runtime
                      # Targets: full, ghidra-only, radare2-only
```

Key decisions:
- **Base image:** `python:3.12-slim-bookworm` (not ubuntu:22.04)
- **JRE 21** via `COPY --from=eclipse-temurin:21-jre-jammy` (not full JDK)
- **Radare2** compiled from `git tag 6.1.2` with meson (--buildtype=release)
- **Non-root user** (`reversetool`)
- **SHA256 verification** of Ghidra download
- **Ghidra slimming** — remove docs/Extensions/GUI (~200MB savings)

### Estimated Image Sizes

| Image | Size |
|-------|------|
| full (Ghidra + JRE + Radare2) | ~900MB |
| ghidra-only | ~750MB |
| radare2-only | ~200MB |

### Usage

```bash
# Zero-config usage
docker run -v $(pwd)/samples:/data:ro -v $(pwd)/out:/output \
  reverse-tool opcode -b ghidra -d /data -o /output

# Interactive debugging
docker run -it --entrypoint bash reverse-tool

# Version check
docker run reverse-tool --version
```

### Tag Strategy

```
reverse-tool:latest          # Latest stable
reverse-tool:1.0.0           # Exact version (immutable)
reverse-tool:1.0             # Minor series latest
reverse-tool:1.0.0-ghidra    # Ghidra-only variant
reverse-tool:1.0.0-radare2   # Radare2-only variant
```

---

## 10. Testing Strategy

### Test Pyramid

```
         /  E2E  \          ~5%   Both backends + real binaries
        /----------\
       / Integration\       ~20%  Single real backend (Docker)
      /--------------\
     /   Unit Tests   \     ~75%  NullBackend + binary_factory
    /___________________\
```

### NullBackend

Programmable deterministic data source:
- Returns predetermined functions/opcodes/metadata
- Can simulate failures (`raise_on_analyze`)
- Can simulate delays (`analyze_delay_seconds`)
- Zero external dependencies

### BinaryFactory

Generates test binaries on-the-fly:
- `minimal_elf_x86_64()` — hand-crafted ~120 byte ELF
- `c_compiled(source)` — compiles C snippet with gcc
- Session-scoped fixtures (cached, idempotent)
- No checked-in binary files in git

### Cross-Backend Consistency

Tolerance thresholds:
- Function discovery (Jaccard): >= 0.80
- Opcode mnemonics (SequenceMatcher): >= 0.90
- Call graph edges (Jaccard): >= 0.85

### pytest Markers

```
unit          — No external tools (default: runs always)
integration   — Requires one real backend
cross_backend — Requires both backends
ghidra        — Auto-skipped if Ghidra unavailable
radare2       — Auto-skipped if Radare2 unavailable
docker        — Tests Docker images
slow          — Execution > 10s
```

### Recommended pytest Plugins

- `pytest-cov` — Coverage (fail_under=85)
- `pytest-xdist` — Parallel test execution
- `pytest-timeout` — Per-test timeout enforcement
- `pytest-randomly` — Randomize order to catch hidden state deps
- `hypothesis` — Property-based testing for writers

---

## 11. CI/CD Pipeline

### Workflow Structure

```
ci.yml:
  lint (ruff + mypy) ─────┐
  unit-test (3.12) ───────┤
                           ├─→ build-images (matrix: full/ghidra/radare2)
                           │     ├─→ integration-test (in container)
                           │     └─→ trivy-scan
                           │
release.yml (on tag v*):
  pypi (Trusted Publishing OIDC) ─┐
  docker (push to GHCR + DockerHub) ──┤
  github-release (changelog + artifacts) ─┘
```

### Security Practices

- GitHub Actions pinned by SHA (not version tag)
- PyPI Trusted Publishing (OIDC, no API token)
- Trivy scan before push
- pip-audit weekly schedule
- Dependabot for pip + github-actions + docker

---

## 12. Dependencies

### pyproject.toml

```toml
[project]
name = "reverse-tool"
dynamic = ["version"]
requires-python = ">=3.12"
dependencies = [
    "click>=8.1",
    "rich>=13.0",
    "rich-click>=1.7",
]

[project.optional-dependencies]
ghidra = ["pyghidra>=1.0"]
radare2 = ["r2pipe>=1.9"]
dev = [
    "ruff",
    "mypy",
    "pytest>=8.0",
    "pytest-cov>=5.0",
    "pytest-xdist>=3.5",
    "pytest-timeout>=2.3",
    "pytest-randomly>=3.15",
    "hypothesis>=6.100",
    "pre-commit",
]
docs = [
    "mkdocs-material",
    "mkdocstrings[python]",
]

[project.scripts]
reverse-tool = "reverse_tool.cli:cli"
```

Backend dependencies are optional groups — users only install what they need.
Lazy imports ensure missing backends don't crash the tool.

---

## 13. Open Source Infrastructure

### README Sections (in order)

1. Badges (PyPI, CI, License, Downloads — max 6)
2. One-line description
3. Highlights (4 bullet points)
4. Quick Start (pip + Docker, copy-paste-run in 60s)
5. Example Output (real formatted output)
6. Supported Extractors (table)
7. Installation (detailed: pip, source, Docker)
8. Architecture Overview (mermaid diagram)
9. Adding a Custom Extractor (5-line code example)
10. Contributing (link to CONTRIBUTING.md)
11. Citation
12. License

### Issue Templates

3 YAML templates with form validation:
- **Bug Report** — version, backend, OS, steps to reproduce
- **Feature Request** — problem statement, proposed solution, scope
- **Extractor Proposal** — description, use case, expected output schema

### PR Template Checklist

- Code style (just lint passes)
- Tests added
- CHANGELOG updated
- Type hints updated
- AI-assisted code disclosure (required)

### Versioning

- SemVer (not CalVer)
- CHANGELOG in Keep a Changelog format
- Release triggered by git tag → automated PyPI + Docker + GitHub Release

### Documentation

- MkDocs Material + GitHub Pages
- Auto-generated API docs via mkdocstrings
- Architecture Decision Records (ADRs) in docs/development/adrs/

---

## 14. Migration Notes

### From OpCodeReverseTool

- `opcode_tool/` → `reverse_tool/extractors/opcode/`
- `opcode_tool/backends/ghidra.py` extraction logic → `extractors/opcode/_ghidra.py`
- `opcode_tool/backends/radare2.py` extraction logic → `extractors/opcode/_radare2.py`
- `opcode_tool/common.py` → split into `engine.py` + `discovery.py` + `config.py`
- Ghidra scripts must migrate from Jython to PyGhidra (Python 3)
- CSV output format preserved

### From FunctionCallReverseTool

- `function_call_tool/` → `reverse_tool/extractors/function_call/`
- Same backend split as opcode
- DOT + JSON output format preserved
- Ghidra scripts must migrate to PyGhidra

### Shared Code Deduplication

- Both `common.py` files → unified `engine.py`
- Both `backends/base.py` → unified `backends/_base.py`
- Both CLI parsers → unified Click-based `cli.py`
- Both deployment-scripts → unified `docker/Dockerfile`
