# Phase 1: Core Framework Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the core framework (backends, extractors, engine, discovery, CLI) so that Phase 2 can plug in real extractor implementations.

**Architecture:** src-layout Python package using Click for CLI, Generic ABC for backends, `__init_subclass__` auto-discovery for extractors, ProcessPoolExecutor for parallel processing. NullBackend enables full unit testing without Ghidra/Radare2.

**Tech Stack:** Python 3.12, Click, Rich, rich-click, pytest, ruff, mypy

**Spec:** `docs/superpowers/specs/2026-04-01-reverse-tool-unified-design.md`

---

## File Map

| File | Responsibility |
|------|---------------|
| `pyproject.toml` | Package metadata, dependencies, entry point, tool config |
| `src/reverse_tool/__init__.py` | Public API, `__version__` |
| `src/reverse_tool/__main__.py` | `python -m reverse_tool` entry |
| `src/reverse_tool/py.typed` | PEP 561 marker |
| `src/reverse_tool/_typing.py` | Shared type aliases (`T_Session`) |
| `src/reverse_tool/exceptions.py` | Structured exception hierarchy |
| `src/reverse_tool/backends/__init__.py` | Re-export `BaseBackend`, `get_backend()` |
| `src/reverse_tool/backends/_base.py` | `BaseBackend(ABC, Generic[T_Session])` |
| `src/reverse_tool/backends/null.py` | Programmable `NullBackend` for testing |
| `src/reverse_tool/extractors/__init__.py` | Re-export `BaseExtractor` |
| `src/reverse_tool/extractors/_base.py` | `BaseExtractor` ABC with `__init_subclass__` |
| `src/reverse_tool/discovery.py` | Registry + `pkgutil` scanning |
| `src/reverse_tool/engine.py` | `process_files()`, `TaskResult`, `ProgressCallback` |
| `src/reverse_tool/config.py` | TOML config loading with priority chain |
| `src/reverse_tool/cli.py` | Click CLI, `ExtractorGroup`, `doctor`, `backends` |
| `tests/conftest.py` | Shared fixtures (NullBackend configs, tmp dirs) |
| `tests/unit/test_exceptions.py` | Exception hierarchy tests |
| `tests/unit/test_backends.py` | BaseBackend + NullBackend tests |
| `tests/unit/test_extractors.py` | BaseExtractor + auto-registration tests |
| `tests/unit/test_discovery.py` | Discovery system tests |
| `tests/unit/test_engine.py` | Parallel processing tests |
| `tests/unit/test_config.py` | Config loading tests |
| `tests/unit/test_cli.py` | CLI integration tests (Click CliRunner) |

---

### Task 1: Project Scaffolding

**Files:**
- Create: `pyproject.toml`
- Create: `src/reverse_tool/__init__.py`
- Create: `src/reverse_tool/__main__.py`
- Create: `src/reverse_tool/py.typed`

- [ ] **Step 1: Create directory structure**

```bash
mkdir -p src/reverse_tool/backends src/reverse_tool/extractors tests/unit
```

- [ ] **Step 2: Write pyproject.toml**

```toml
[build-system]
requires = ["setuptools>=69"]
build-backend = "setuptools.build_meta"

[project]
name = "reverse-tool"
version = "0.1.0"
description = "Binary analysis feature extraction framework"
readme = "README.md"
license = {text = "MIT"}
requires-python = ">=3.12"
authors = [{name = "PolinLai"}]
keywords = [
    "reverse-engineering", "binary-analysis", "malware-analysis",
    "ghidra", "radare2", "feature-extraction",
]
classifiers = [
    "Development Status :: 3 - Alpha",
    "License :: OSI Approved :: MIT License",
    "Programming Language :: Python :: 3",
    "Programming Language :: Python :: 3.12",
    "Operating System :: POSIX :: Linux",
    "Topic :: Security",
    "Intended Audience :: Developers",
    "Intended Audience :: Science/Research",
    "Typing :: Typed",
]
dependencies = [
    "click>=8.1",
    "rich>=13.0",
    "rich-click>=1.7",
]

[project.urls]
Homepage = "https://github.com/bolin8017/ReverseTool"
Repository = "https://github.com/bolin8017/ReverseTool"
"Bug Tracker" = "https://github.com/bolin8017/ReverseTool/issues"
Changelog = "https://github.com/bolin8017/ReverseTool/blob/main/CHANGELOG.md"

[project.optional-dependencies]
ghidra = ["pyghidra>=1.0"]
radare2 = ["r2pipe>=1.9"]
dev = [
    "ruff>=0.11",
    "mypy>=1.10",
    "pytest>=8.0",
    "pytest-cov>=5.0",
    "pytest-timeout>=2.3",
    "pre-commit",
]

[project.scripts]
reverse-tool = "reverse_tool.cli:cli"

[tool.setuptools.packages.find]
where = ["src"]

[tool.setuptools.package-data]
reverse_tool = ["py.typed"]

[tool.ruff]
target-version = "py312"
line-length = 88
src = ["src", "tests"]

[tool.ruff.lint]
select = ["E", "F", "W", "I", "UP", "B", "SIM"]

[tool.mypy]
python_version = "3.12"
strict = false
warn_return_any = true
warn_unused_configs = true
ignore_missing_imports = true

[tool.pytest.ini_options]
testpaths = ["tests"]
markers = [
    "unit: No external tool dependencies",
    "integration: Requires a real backend",
    "ghidra: Requires Ghidra backend",
    "radare2: Requires Radare2 backend",
]
addopts = "-m unit --strict-markers --tb=short --timeout=30"
```

- [ ] **Step 3: Write package files**

`src/reverse_tool/__init__.py`:
```python
"""ReverseTool - Binary analysis feature extraction framework."""

__version__ = "0.1.0"
```

`src/reverse_tool/__main__.py`:
```python
"""Allow running with ``python -m reverse_tool``."""

from reverse_tool.cli import cli

if __name__ == "__main__":
    cli()
```

`src/reverse_tool/py.typed`:
```
```
(empty file — PEP 561 marker)

- [ ] **Step 4: Install in editable mode and verify**

Run: `pip install -e ".[dev]"`
Expected: Installs successfully

Run: `python -c "import reverse_tool; print(reverse_tool.__version__)"`
Expected: `0.1.0`

- [ ] **Step 5: Commit**

```bash
git add pyproject.toml src/ tests/
git commit -m "feat: project scaffolding with src layout and pyproject.toml"
```

---

### Task 2: Exception Hierarchy

**Files:**
- Create: `src/reverse_tool/exceptions.py`
- Create: `tests/unit/test_exceptions.py`

- [ ] **Step 1: Write the failing test**

`tests/unit/test_exceptions.py`:
```python
import pytest

from reverse_tool.exceptions import (
    ReverseToolError,
    BackendError,
    BackendNotAvailable,
    BackendVersionError,
    BackendTimeout,
    ExtractionError,
    IncompatibleBackendError,
    OutputWriteError,
    ConfigError,
)

pytestmark = pytest.mark.unit


class TestExceptionHierarchy:
    def test_all_inherit_from_reverse_tool_error(self):
        exceptions = [
            BackendError, BackendNotAvailable, BackendVersionError,
            BackendTimeout, ExtractionError, IncompatibleBackendError,
            OutputWriteError, ConfigError,
        ]
        for exc_cls in exceptions:
            assert issubclass(exc_cls, ReverseToolError)

    def test_backend_exceptions_inherit_from_backend_error(self):
        for exc_cls in [BackendNotAvailable, BackendVersionError, BackendTimeout]:
            assert issubclass(exc_cls, BackendError)

    def test_extraction_exceptions_inherit_from_extraction_error(self):
        assert issubclass(IncompatibleBackendError, ExtractionError)

    def test_exceptions_are_catchable_with_base(self):
        with pytest.raises(ReverseToolError):
            raise BackendNotAvailable("ghidra not found")

    def test_backend_not_available_message(self):
        exc = BackendNotAvailable("ghidra", fix="Install Ghidra 12.0.4")
        assert "ghidra" in str(exc)
        assert exc.fix == "Install Ghidra 12.0.4"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/unit/test_exceptions.py -v`
Expected: FAIL (ImportError)

- [ ] **Step 3: Write implementation**

`src/reverse_tool/exceptions.py`:
```python
"""Structured exception hierarchy for ReverseTool."""

from __future__ import annotations


class ReverseToolError(Exception):
    """Base for all framework errors."""


class BackendError(ReverseToolError):
    """Backend-related failures."""


class BackendNotAvailable(BackendError):
    """Backend tool not found or not configured."""

    def __init__(self, backend: str, *, fix: str = "") -> None:
        self.backend = backend
        self.fix = fix
        msg = f"Backend not available: {backend}"
        if fix:
            msg += f". Fix: {fix}"
        super().__init__(msg)


class BackendVersionError(BackendError):
    """Backend version is unsupported."""

    def __init__(self, backend: str, found: str, expected: str) -> None:
        self.backend = backend
        self.found = found
        self.expected = expected
        super().__init__(
            f"{backend}: found version {found}, expected {expected}"
        )


class BackendTimeout(BackendError):
    """Analysis exceeded timeout."""

    def __init__(self, input_file: str, timeout: int) -> None:
        self.input_file = input_file
        self.timeout = timeout
        super().__init__(f"Timeout ({timeout}s) exceeded for {input_file}")


class ExtractionError(ReverseToolError):
    """Extraction-phase failures."""


class IncompatibleBackendError(ExtractionError):
    """Extractor does not support the selected backend."""

    def __init__(self, extractor: str, backend: str,
                 supported: frozenset[str]) -> None:
        self.extractor = extractor
        self.backend = backend
        self.supported = supported
        super().__init__(
            f"Extractor {extractor!r} does not support backend {backend!r}. "
            f"Supported: {', '.join(sorted(supported))}"
        )


class OutputWriteError(ReverseToolError):
    """Failed to write extraction results."""


class ConfigError(ReverseToolError):
    """Configuration file or value error."""
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/unit/test_exceptions.py -v`
Expected: All PASSED

- [ ] **Step 5: Commit**

```bash
git add src/reverse_tool/exceptions.py tests/unit/test_exceptions.py
git commit -m "feat: add structured exception hierarchy"
```

---

### Task 3: Type Aliases and BaseBackend

**Files:**
- Create: `src/reverse_tool/_typing.py`
- Create: `src/reverse_tool/backends/_base.py`
- Create: `src/reverse_tool/backends/__init__.py`
- Create: `tests/unit/test_backends.py`

- [ ] **Step 1: Write the failing test**

`tests/unit/test_backends.py`:
```python
import pytest
from dataclasses import FrozenInstanceError
from pathlib import Path

from reverse_tool.backends import BaseBackend, BackendInfo

pytestmark = pytest.mark.unit


class TestBackendInfo:
    def test_is_frozen_dataclass(self):
        info = BackendInfo(name="test", version="1.0")
        assert info.name == "test"
        assert info.version == "1.0"
        with pytest.raises(FrozenInstanceError):
            info.name = "other"


class ConcreteBackend(BaseBackend[str]):
    @property
    def info(self) -> BackendInfo:
        return BackendInfo(name="concrete", version="1.0")

    def validate_environment(self) -> None:
        pass

    def _open_session(self, input_file: Path, timeout: int) -> str:
        return f"session:{input_file}"

    def _close_session(self, session: str) -> None:
        pass


class TestBaseBackend:
    def test_session_context_manager(self, tmp_path: Path):
        binary = tmp_path / "test.bin"
        binary.write_bytes(b"\x00")
        backend = ConcreteBackend()

        with backend.session(binary, timeout=60) as session:
            assert session == f"session:{binary}"

    def test_session_closes_on_exception(self, tmp_path: Path):
        class TrackingBackend(BaseBackend[str]):
            closed = False

            @property
            def info(self) -> BackendInfo:
                return BackendInfo(name="tracking", version="1.0")

            def validate_environment(self) -> None:
                pass

            def _open_session(self, input_file: Path, timeout: int) -> str:
                return "open"

            def _close_session(self, session: str) -> None:
                TrackingBackend.closed = True

        backend = TrackingBackend()
        binary = tmp_path / "test.bin"
        binary.write_bytes(b"\x00")

        with pytest.raises(RuntimeError):
            with backend.session(binary) as session:
                raise RuntimeError("crash")

        assert TrackingBackend.closed is True

    def test_cannot_instantiate_abstract(self):
        with pytest.raises(TypeError):
            BaseBackend()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/unit/test_backends.py -v`
Expected: FAIL (ImportError)

- [ ] **Step 3: Write _typing.py**

`src/reverse_tool/_typing.py`:
```python
"""Internal type aliases for ReverseTool."""

from __future__ import annotations

from typing import TypeVar

T_Session = TypeVar("T_Session")
```

- [ ] **Step 4: Write backends/_base.py**

`src/reverse_tool/backends/_base.py`:
```python
"""Abstract base class for reverse engineering backends."""

from __future__ import annotations

from abc import ABC, abstractmethod
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Generic, Iterator

from reverse_tool._typing import T_Session


@dataclass(frozen=True)
class BackendInfo:
    """Immutable backend metadata."""

    name: str
    version: str


class BaseBackend(ABC, Generic[T_Session]):
    """A backend provides a reverse engineering tool (Ghidra, Radare2, etc.).

    Subclasses implement ``_open_session`` and ``_close_session``.
    Callers use the ``session`` context manager — never call open/close directly.
    """

    @property
    @abstractmethod
    def info(self) -> BackendInfo:
        """Backend name and version."""
        ...

    @abstractmethod
    def validate_environment(self) -> None:
        """Check that the backend tool is installed and usable.

        Raises:
            BackendNotAvailable: If prerequisites are missing.
        """
        ...

    @abstractmethod
    def _open_session(self, input_file: Path, timeout: int) -> T_Session:
        """Open an analysis session. Called by ``session()``."""
        ...

    @abstractmethod
    def _close_session(self, session: T_Session) -> None:
        """Close an analysis session. Called by ``session()``."""
        ...

    @contextmanager
    def session(
        self, input_file: Path, timeout: int = 600
    ) -> Iterator[T_Session]:
        """Context manager for backend session lifecycle.

        This is the ONLY public API for session management.
        """
        s = self._open_session(input_file, timeout)
        try:
            yield s
        finally:
            self._close_session(s)
```

- [ ] **Step 5: Write backends/__init__.py**

`src/reverse_tool/backends/__init__.py`:
```python
"""Backend infrastructure for ReverseTool."""

from reverse_tool.backends._base import BackendInfo, BaseBackend

__all__ = ["BackendInfo", "BaseBackend"]
```

- [ ] **Step 6: Create empty extractors/__init__.py**

`src/reverse_tool/extractors/__init__.py`:
```python
"""Extractor infrastructure for ReverseTool."""
```

- [ ] **Step 7: Run tests**

Run: `pytest tests/unit/test_backends.py -v`
Expected: All PASSED

- [ ] **Step 8: Commit**

```bash
git add src/reverse_tool/_typing.py src/reverse_tool/backends/ src/reverse_tool/extractors/__init__.py tests/unit/test_backends.py
git commit -m "feat: add BaseBackend ABC with Generic session and context manager"
```

---

### Task 4: NullBackend

**Files:**
- Create: `src/reverse_tool/backends/null.py`
- Create: `tests/conftest.py`
- Modify: `tests/unit/test_backends.py` (append tests)

- [ ] **Step 1: Write the failing test**

Append to `tests/unit/test_backends.py`:
```python
from reverse_tool.backends.null import NullBackend, NullBackendConfig


class TestNullBackend:
    def test_returns_configured_data(self, tmp_path: Path):
        config = NullBackendConfig(
            functions={"main": {"addr": 0x1000, "calls": ["exit"]}},
            opcodes={"main": ["push", "mov", "ret"]},
        )
        backend = NullBackend(config)
        binary = tmp_path / "test.bin"
        binary.write_bytes(b"\x00")

        with backend.session(binary) as session:
            assert session.functions == config.functions
            assert session.opcodes == config.opcodes

    def test_default_config_returns_empty(self, tmp_path: Path):
        backend = NullBackend()
        binary = tmp_path / "test.bin"
        binary.write_bytes(b"\x00")

        with backend.session(binary) as session:
            assert session.functions == {}
            assert session.opcodes == {}

    def test_simulate_failure(self, tmp_path: Path):
        config = NullBackendConfig(
            raise_on_open=RuntimeError("Ghidra crashed"),
        )
        backend = NullBackend(config)
        binary = tmp_path / "test.bin"
        binary.write_bytes(b"\x00")

        with pytest.raises(RuntimeError, match="Ghidra crashed"):
            with backend.session(binary) as session:
                pass

    def test_validate_environment_always_passes(self):
        backend = NullBackend()
        backend.validate_environment()  # should not raise

    def test_info(self):
        backend = NullBackend()
        assert backend.info.name == "null"
        assert backend.info.version == "0.0.0"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/unit/test_backends.py::TestNullBackend -v`
Expected: FAIL (ImportError)

- [ ] **Step 3: Write NullBackend**

`src/reverse_tool/backends/null.py`:
```python
"""Programmable null backend for testing."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from reverse_tool.backends._base import BackendInfo, BaseBackend


@dataclass
class NullSession:
    """Session returned by NullBackend. Holds predetermined data."""

    binary_path: Path
    functions: dict[str, Any] = field(default_factory=dict)
    opcodes: dict[str, list[str]] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class NullBackendConfig:
    """Configuration for NullBackend behavior."""

    functions: dict[str, Any] = field(default_factory=dict)
    opcodes: dict[str, list[str]] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
    raise_on_open: Exception | None = None


class NullBackend(BaseBackend[NullSession]):
    """A programmable backend that returns predetermined data.

    Designed for unit testing — zero external dependencies.
    """

    def __init__(self, config: NullBackendConfig | None = None) -> None:
        self._config = config or NullBackendConfig()

    @property
    def info(self) -> BackendInfo:
        return BackendInfo(name="null", version="0.0.0")

    def validate_environment(self) -> None:
        pass

    def _open_session(self, input_file: Path, timeout: int) -> NullSession:
        if self._config.raise_on_open is not None:
            raise self._config.raise_on_open
        return NullSession(
            binary_path=input_file,
            functions=dict(self._config.functions),
            opcodes=dict(self._config.opcodes),
            metadata=dict(self._config.metadata),
        )

    def _close_session(self, session: NullSession) -> None:
        pass
```

- [ ] **Step 4: Write conftest.py with shared fixtures**

`tests/conftest.py`:
```python
"""Shared test fixtures for ReverseTool."""

import pytest

from reverse_tool.backends.null import NullBackend, NullBackendConfig

MINIMAL_DATA = NullBackendConfig(
    functions={
        "main": {"addr": 0x401000, "size": 42, "calls": ["printf", "exit"]},
        "printf": {"addr": 0x401100, "size": 10, "calls": []},
        "exit": {"addr": 0x401200, "size": 8, "calls": []},
    },
    opcodes={
        "main": ["push", "mov", "sub", "call", "call", "add", "ret"],
        "printf": ["push", "mov", "ret"],
        "exit": ["mov", "syscall"],
    },
    metadata={"arch": "x86_64", "format": "ELF"},
)

EMPTY_DATA = NullBackendConfig()


@pytest.fixture
def null_backend() -> NullBackend:
    return NullBackend(MINIMAL_DATA)


@pytest.fixture
def empty_null_backend() -> NullBackend:
    return NullBackend(EMPTY_DATA)


@pytest.fixture
def failing_backend() -> NullBackend:
    return NullBackend(NullBackendConfig(
        raise_on_open=RuntimeError("Backend crashed"),
    ))
```

- [ ] **Step 5: Run tests**

Run: `pytest tests/unit/test_backends.py -v`
Expected: All PASSED

- [ ] **Step 6: Commit**

```bash
git add src/reverse_tool/backends/null.py tests/conftest.py tests/unit/test_backends.py
git commit -m "feat: add programmable NullBackend for testing"
```

---

### Task 5: BaseExtractor with Auto-Registration

**Files:**
- Create: `src/reverse_tool/extractors/_base.py`
- Create: `src/reverse_tool/discovery.py`
- Modify: `src/reverse_tool/extractors/__init__.py`
- Create: `tests/unit/test_extractors.py`

- [ ] **Step 1: Write the failing test**

`tests/unit/test_extractors.py`:
```python
import logging
import pytest
from pathlib import Path

from reverse_tool.backends import BackendInfo
from reverse_tool.extractors import BaseExtractor, ExtractResult

pytestmark = pytest.mark.unit


class TestExtractResult:
    def test_is_frozen(self):
        result = ExtractResult(
            extractor_name="test",
            input_file=Path("/tmp/test"),
            data={"key": "val"},
        )
        assert result.extractor_name == "test"
        assert result.metadata == {}


class TestBaseExtractor:
    def test_cannot_instantiate_abstract(self):
        with pytest.raises(TypeError):
            BaseExtractor()

    def test_concrete_extractor_registered(self):
        """Concrete subclasses auto-register via __init_subclass__."""
        from reverse_tool.discovery import _EXTRACTOR_REGISTRY

        class DummyExtractor(BaseExtractor):
            @property
            def name(self) -> str:
                return "dummy_test"

            @property
            def description(self) -> str:
                return "Test extractor"

            @property
            def supported_backends(self) -> frozenset[str]:
                return frozenset({"null"})

            def extract(self, session, input_file, logger):
                return ExtractResult(
                    extractor_name=self.name,
                    input_file=input_file,
                    data={},
                )

            def write_output(self, result, output_dir):
                return []

        assert "dummy_test" in _EXTRACTOR_REGISTRY

    def test_supports_backend(self):
        class CheckExtractor(BaseExtractor):
            @property
            def name(self) -> str:
                return "check_test"

            @property
            def description(self) -> str:
                return "Check"

            @property
            def supported_backends(self) -> frozenset[str]:
                return frozenset({"ghidra", "radare2"})

            def extract(self, session, input_file, logger):
                return ExtractResult(
                    extractor_name=self.name, input_file=input_file, data={}
                )

            def write_output(self, result, output_dir):
                return []

        ext = CheckExtractor()
        from reverse_tool.backends._base import BackendInfo

        class FakeBackend:
            info = BackendInfo(name="ghidra", version="12.0.4")

        assert ext.supports_backend(FakeBackend()) is True

        class FakeBackend2:
            info = BackendInfo(name="ida", version="8.0")

        assert ext.supports_backend(FakeBackend2()) is False
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/unit/test_extractors.py -v`
Expected: FAIL (ImportError)

- [ ] **Step 3: Write discovery.py**

`src/reverse_tool/discovery.py`:
```python
"""Extractor auto-discovery and registration."""

from __future__ import annotations

import importlib
import logging
import pkgutil
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from reverse_tool.extractors._base import BaseExtractor

logger = logging.getLogger(__name__)

_EXTRACTOR_REGISTRY: dict[str, type[BaseExtractor]] = {}


def _register_extractor(cls: type[BaseExtractor]) -> None:
    """Called by BaseExtractor.__init_subclass__. Internal API."""
    name = cls.name.fget(cls)  # type: ignore[attr-defined]
    if name in _EXTRACTOR_REGISTRY:
        existing = _EXTRACTOR_REGISTRY[name]
        if existing is not cls:
            raise ImportError(
                f"Duplicate extractor name {name!r}: "
                f"{cls!r} conflicts with {existing!r}"
            )
        return
    _EXTRACTOR_REGISTRY[name] = cls
    logger.debug("Registered extractor: %s (%s)", name, cls.__module__)


def discover_extractors() -> dict[str, type[BaseExtractor]]:
    """Import all extractor subpackages to trigger __init_subclass__ registration.

    Returns:
        Dict mapping extractor names to their classes.
    """
    import reverse_tool.extractors as ext_pkg

    for _finder, module_name, _is_pkg in pkgutil.walk_packages(
        ext_pkg.__path__, prefix=ext_pkg.__name__ + "."
    ):
        try:
            importlib.import_module(module_name)
        except ImportError as e:
            logger.warning("Skipping %s: %s", module_name, e)

    return dict(_EXTRACTOR_REGISTRY)


def get_extractor(name: str) -> type[BaseExtractor]:
    """Get a single extractor by name.

    Raises:
        KeyError: If extractor name is not found.
    """
    registry = discover_extractors()
    try:
        return registry[name]
    except KeyError:
        available = ", ".join(sorted(registry)) or "(none)"
        raise KeyError(
            f"Unknown extractor {name!r}. Available: {available}"
        ) from None
```

- [ ] **Step 4: Write extractors/_base.py**

`src/reverse_tool/extractors/_base.py`:
```python
"""Abstract base class for feature extractors."""

from __future__ import annotations

import inspect
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Generic

from reverse_tool._typing import T_Session


@dataclass(frozen=True)
class ExtractResult:
    """Immutable extraction result."""

    extractor_name: str
    input_file: Path
    data: dict[str, Any]
    metadata: dict[str, Any] = field(default_factory=dict)


class BaseExtractor(ABC, Generic[T_Session]):
    """A feature extractor produces structured output from a backend session.

    Concrete subclasses are auto-registered via ``__init_subclass__``.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique extractor identifier (e.g. 'opcode', 'function_call')."""
        ...

    @property
    @abstractmethod
    def description(self) -> str:
        """Short human-readable description."""
        ...

    @property
    @abstractmethod
    def supported_backends(self) -> frozenset[str]:
        """Set of backend names this extractor supports."""
        ...

    @abstractmethod
    def extract(
        self,
        session: T_Session,
        input_file: Path,
        logger: logging.Logger,
    ) -> ExtractResult:
        """Extract features from a backend session."""
        ...

    @abstractmethod
    def write_output(
        self, result: ExtractResult, output_dir: Path
    ) -> list[Path]:
        """Write results to disk. Returns paths of created files."""
        ...

    def supports_backend(self, backend: Any) -> bool:
        """Check if this extractor supports the given backend."""
        return backend.info.name in self.supported_backends

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        if inspect.isabstract(cls):
            return
        from reverse_tool.discovery import _register_extractor

        _register_extractor(cls)
```

- [ ] **Step 5: Update extractors/__init__.py**

`src/reverse_tool/extractors/__init__.py`:
```python
"""Extractor infrastructure for ReverseTool."""

from reverse_tool.extractors._base import BaseExtractor, ExtractResult

__all__ = ["BaseExtractor", "ExtractResult"]
```

- [ ] **Step 6: Run tests**

Run: `pytest tests/unit/test_extractors.py -v`
Expected: All PASSED

- [ ] **Step 7: Commit**

```bash
git add src/reverse_tool/discovery.py src/reverse_tool/extractors/ tests/unit/test_extractors.py
git commit -m "feat: add BaseExtractor with __init_subclass__ auto-registration"
```

---

### Task 6: Discovery System Tests

**Files:**
- Create: `tests/unit/test_discovery.py`

- [ ] **Step 1: Write the test**

`tests/unit/test_discovery.py`:
```python
import pytest

from reverse_tool.discovery import (
    _EXTRACTOR_REGISTRY,
    discover_extractors,
    get_extractor,
)

pytestmark = pytest.mark.unit


class TestDiscovery:
    def test_discover_returns_dict(self):
        result = discover_extractors()
        assert isinstance(result, dict)

    def test_get_extractor_unknown_raises_key_error(self):
        with pytest.raises(KeyError, match="Unknown extractor"):
            get_extractor("nonexistent_extractor_xyz")

    def test_registry_is_populated_by_subclassing(self):
        """Extractors defined in test_extractors.py should be in registry."""
        # Import to trigger registration
        import tests.unit.test_extractors  # noqa: F401

        assert "dummy_test" in _EXTRACTOR_REGISTRY
```

- [ ] **Step 2: Run tests**

Run: `pytest tests/unit/test_discovery.py -v`
Expected: All PASSED

- [ ] **Step 3: Commit**

```bash
git add tests/unit/test_discovery.py
git commit -m "test: add discovery system tests"
```

---

### Task 7: Engine (Parallel Processing)

**Files:**
- Create: `src/reverse_tool/engine.py`
- Create: `tests/unit/test_engine.py`

- [ ] **Step 1: Write the failing test**

`tests/unit/test_engine.py`:
```python
import logging
import pytest
from pathlib import Path
from typing import Any

from reverse_tool.backends import BaseBackend, BackendInfo
from reverse_tool.backends.null import NullBackend, NullBackendConfig, NullSession
from reverse_tool.engine import TaskResult, process_files, collect_files
from reverse_tool.extractors import BaseExtractor, ExtractResult

pytestmark = pytest.mark.unit


class StubExtractor(BaseExtractor[NullSession]):
    @property
    def name(self) -> str:
        return "stub"

    @property
    def description(self) -> str:
        return "Stub for testing"

    @property
    def supported_backends(self) -> frozenset[str]:
        return frozenset({"null"})

    def extract(self, session, input_file, logger):
        return ExtractResult(
            extractor_name=self.name,
            input_file=input_file,
            data={"opcodes": session.opcodes},
        )

    def write_output(self, result, output_dir):
        out = output_dir / f"{result.input_file.stem}.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text("{}")
        return [out]


class TestCollectFiles:
    def test_collects_files_without_extension(self, tmp_path: Path):
        (tmp_path / "abc123").write_bytes(b"\x00")
        (tmp_path / "def456").write_bytes(b"\x00")
        (tmp_path / "readme.txt").write_text("ignore me")
        files = collect_files(tmp_path)
        names = [f.name for f in files]
        assert "abc123" in names
        assert "def456" in names
        assert "readme.txt" not in names

    def test_collects_with_pattern(self, tmp_path: Path):
        (tmp_path / "mal.exe").write_bytes(b"\x00")
        (tmp_path / "mal.dll").write_bytes(b"\x00")
        (tmp_path / "readme.txt").write_text("ignore")
        files = collect_files(tmp_path, pattern="*.exe")
        assert len(files) == 1
        assert files[0].name == "mal.exe"

    def test_empty_directory(self, tmp_path: Path):
        files = collect_files(tmp_path)
        assert files == []


class TestProcessFiles:
    def test_single_file_success(self, tmp_path: Path):
        binary = tmp_path / "input" / "test_bin"
        binary.parent.mkdir()
        binary.write_bytes(b"\x00")
        output = tmp_path / "output"

        results = list(process_files(
            files=[binary],
            backend_cls=NullBackend,
            backend_config=NullBackendConfig(
                opcodes={"main": ["push", "ret"]},
            ),
            extractor_cls=StubExtractor,
            output_dir=output,
            max_workers=1,
            timeout=60,
        ))
        assert len(results) == 1
        assert results[0].success is True
        assert len(results[0].output_files) == 1

    def test_handles_backend_failure(self, tmp_path: Path):
        binary = tmp_path / "test_bin"
        binary.write_bytes(b"\x00")
        output = tmp_path / "output"

        results = list(process_files(
            files=[binary],
            backend_cls=NullBackend,
            backend_config=NullBackendConfig(
                raise_on_open=RuntimeError("crash"),
            ),
            extractor_cls=StubExtractor,
            output_dir=output,
            max_workers=1,
            timeout=60,
        ))
        assert len(results) == 1
        assert results[0].success is False
        assert "crash" in results[0].error

    def test_multiple_files(self, tmp_path: Path):
        input_dir = tmp_path / "input"
        input_dir.mkdir()
        for i in range(5):
            (input_dir / f"bin_{i}").write_bytes(b"\x00")
        output = tmp_path / "output"
        files = list(input_dir.iterdir())

        results = list(process_files(
            files=files,
            backend_cls=NullBackend,
            backend_config=NullBackendConfig(),
            extractor_cls=StubExtractor,
            output_dir=output,
            max_workers=1,
            timeout=60,
        ))
        assert len(results) == 5
        assert all(r.success for r in results)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/unit/test_engine.py -v`
Expected: FAIL (ImportError)

- [ ] **Step 3: Write engine.py**

`src/reverse_tool/engine.py`:
```python
"""Parallel processing engine for ReverseTool."""

from __future__ import annotations

import fnmatch
import logging
import os
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator, Protocol

from reverse_tool.backends._base import BaseBackend
from reverse_tool.extractors._base import BaseExtractor, ExtractResult

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class TaskResult:
    """Result of processing a single binary file."""

    input_file: Path
    success: bool
    output_files: list[Path] = field(default_factory=list)
    error: str | None = None
    elapsed: float = 0.0


class ProgressCallback(Protocol):
    """Protocol for progress reporting. CLI layer injects implementation."""

    def on_start(self, total_files: int) -> None: ...
    def on_file_complete(self, result: TaskResult) -> None: ...
    def on_finish(self, results: list[TaskResult]) -> None: ...


def collect_files(
    directory: Path, *, pattern: str | None = None
) -> list[Path]:
    """Collect binary files from directory.

    Args:
        directory: Root directory to scan.
        pattern: Glob pattern. Default (None) matches files without extensions.

    Returns:
        Sorted list of file paths.
    """
    files = []
    for root, _, filenames in os.walk(directory):
        for filename in filenames:
            if pattern:
                if not fnmatch.fnmatch(filename, pattern):
                    continue
            else:
                if "." in filename:
                    continue
            files.append(Path(root) / filename)
    files.sort()
    return files


def _process_single_file(
    input_file: Path,
    backend_cls: type[BaseBackend],
    backend_config: Any,
    extractor_cls: type[BaseExtractor],
    output_dir: Path,
    timeout: int,
) -> TaskResult:
    """Worker function. Runs in a separate process.

    Receives classes (not instances) because classes are picklable.
    Each worker creates its own backend + extractor + session.
    """
    import time

    log = logging.getLogger(f"worker.{input_file.stem}")
    start = time.perf_counter()

    try:
        backend = backend_cls(backend_config) if backend_config is not None else backend_cls()
        extractor = extractor_cls()

        with backend.session(input_file, timeout=timeout) as session:
            result = extractor.extract(session, input_file, log)
            file_output_dir = output_dir / input_file.stem
            file_output_dir.mkdir(parents=True, exist_ok=True)
            written = extractor.write_output(result, file_output_dir)

        elapsed = time.perf_counter() - start
        return TaskResult(
            input_file=input_file,
            success=True,
            output_files=written,
            elapsed=elapsed,
        )
    except Exception as exc:
        elapsed = time.perf_counter() - start
        log.error("Failed to process %s: %s", input_file, exc)
        return TaskResult(
            input_file=input_file,
            success=False,
            error=str(exc),
            elapsed=elapsed,
        )


def process_files(
    files: list[Path],
    backend_cls: type[BaseBackend],
    extractor_cls: type[BaseExtractor],
    output_dir: Path,
    *,
    backend_config: Any = None,
    max_workers: int | None = None,
    timeout: int = 600,
    progress: ProgressCallback | None = None,
) -> Iterator[TaskResult]:
    """Process files, yielding results as they complete.

    Uses sequential processing when max_workers=1 (easier debugging).
    Uses ProcessPoolExecutor otherwise (CPU-bound, process isolation).
    """
    if not files:
        return

    if progress:
        progress.on_start(len(files))

    results: list[TaskResult] = []

    if max_workers == 1 or len(files) == 1:
        for f in files:
            result = _process_single_file(
                f, backend_cls, backend_config, extractor_cls,
                output_dir, timeout,
            )
            results.append(result)
            if progress:
                progress.on_file_complete(result)
            yield result
    else:
        workers = max_workers or min(os.cpu_count() or 1, len(files))
        with ProcessPoolExecutor(max_workers=workers) as pool:
            future_to_file = {
                pool.submit(
                    _process_single_file,
                    f, backend_cls, backend_config, extractor_cls,
                    output_dir, timeout,
                ): f
                for f in files
            }
            for future in as_completed(future_to_file):
                result = future.result()
                results.append(result)
                if progress:
                    progress.on_file_complete(result)
                yield result

    if progress:
        progress.on_finish(results)
```

- [ ] **Step 4: Run tests**

Run: `pytest tests/unit/test_engine.py -v`
Expected: All PASSED

- [ ] **Step 5: Commit**

```bash
git add src/reverse_tool/engine.py tests/unit/test_engine.py
git commit -m "feat: add parallel processing engine with ProgressCallback"
```

---

### Task 8: Config Loading

**Files:**
- Create: `src/reverse_tool/config.py`
- Create: `tests/unit/test_config.py`

- [ ] **Step 1: Write the failing test**

`tests/unit/test_config.py`:
```python
import pytest
from pathlib import Path

from reverse_tool.config import load_config, Config

pytestmark = pytest.mark.unit


class TestConfig:
    def test_default_config(self):
        config = Config()
        assert config.default_backend is None
        assert config.timeout == 600
        assert config.ghidra_path is None

    def test_load_from_toml(self, tmp_path: Path):
        toml_file = tmp_path / "config.toml"
        toml_file.write_text("""\
[defaults]
backend = "ghidra"
timeout = 1200

[backends.ghidra]
path = "/opt/ghidra/support/analyzeHeadless"
""")
        config = load_config(toml_file)
        assert config.default_backend == "ghidra"
        assert config.timeout == 1200
        assert config.ghidra_path == "/opt/ghidra/support/analyzeHeadless"

    def test_missing_file_returns_default(self):
        config = load_config(Path("/nonexistent/config.toml"))
        assert config.default_backend is None

    def test_malformed_toml_raises_config_error(self, tmp_path: Path):
        toml_file = tmp_path / "bad.toml"
        toml_file.write_text("[[invalid toml content!!")
        from reverse_tool.exceptions import ConfigError
        with pytest.raises(ConfigError):
            load_config(toml_file)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/unit/test_config.py -v`
Expected: FAIL (ImportError)

- [ ] **Step 3: Write config.py**

`src/reverse_tool/config.py`:
```python
"""Configuration loading for ReverseTool."""

from __future__ import annotations

import logging
import tomllib
from dataclasses import dataclass
from pathlib import Path

from reverse_tool.exceptions import ConfigError

logger = logging.getLogger(__name__)

DEFAULT_CONFIG_PATH = Path.home() / ".config" / "reverse-tool" / "config.toml"


@dataclass
class Config:
    """Resolved configuration values."""

    default_backend: str | None = None
    timeout: int = 600
    max_workers: int | None = None
    ghidra_path: str | None = None
    radare2_analysis_level: str = "aa"


def load_config(path: Path = DEFAULT_CONFIG_PATH) -> Config:
    """Load configuration from TOML file.

    Returns default Config if file does not exist.
    Raises ConfigError on malformed TOML.
    """
    if not path.is_file():
        logger.debug("Config file not found: %s", path)
        return Config()

    try:
        with open(path, "rb") as f:
            data = tomllib.load(f)
    except tomllib.TOMLDecodeError as e:
        raise ConfigError(f"Invalid TOML in {path}: {e}") from e

    defaults = data.get("defaults", {})
    ghidra = data.get("backends", {}).get("ghidra", {})
    radare2 = data.get("backends", {}).get("radare2", {})

    return Config(
        default_backend=defaults.get("backend"),
        timeout=defaults.get("timeout", 600),
        max_workers=defaults.get("max_workers"),
        ghidra_path=ghidra.get("path"),
        radare2_analysis_level=radare2.get("analysis_level", "aa"),
    )
```

- [ ] **Step 4: Run tests**

Run: `pytest tests/unit/test_config.py -v`
Expected: All PASSED

- [ ] **Step 5: Commit**

```bash
git add src/reverse_tool/config.py tests/unit/test_config.py
git commit -m "feat: add TOML config loading with defaults"
```

---

### Task 9: CLI with Click

**Files:**
- Create: `src/reverse_tool/cli.py`
- Create: `tests/unit/test_cli.py`

- [ ] **Step 1: Write the failing test**

`tests/unit/test_cli.py`:
```python
import pytest
from click.testing import CliRunner

from reverse_tool.cli import cli

pytestmark = pytest.mark.unit


@pytest.fixture
def runner():
    return CliRunner()


class TestCLI:
    def test_help(self, runner):
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "reverse-tool" in result.output.lower() or "usage" in result.output.lower()

    def test_version(self, runner):
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "0.1.0" in result.output

    def test_backends_command(self, runner):
        result = runner.invoke(cli, ["backends"])
        assert result.exit_code == 0
        assert "null" in result.output.lower()

    def test_doctor_command(self, runner):
        result = runner.invoke(cli, ["doctor"])
        assert result.exit_code == 0
        assert "python" in result.output.lower()

    def test_unknown_subcommand(self, runner):
        result = runner.invoke(cli, ["nonexistent"])
        assert result.exit_code != 0
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/unit/test_cli.py -v`
Expected: FAIL (ImportError)

- [ ] **Step 3: Write cli.py**

`src/reverse_tool/cli.py`:
```python
"""CLI entry point for ReverseTool."""

from __future__ import annotations

import importlib
import platform
import sys

import rich_click as click

import reverse_tool
from reverse_tool.discovery import discover_extractors

click.rich_click.SHOW_ARGUMENTS = True
click.rich_click.USE_MARKDOWN = True


class ExtractorGroup(click.Group):
    """Click group that auto-discovers extractor subcommands."""

    def list_commands(self, ctx: click.Context) -> list[str]:
        builtin = ["backends", "doctor"]
        extractors = sorted(discover_extractors().keys())
        extractor_cmds = [n.replace("_", "-") for n in extractors]
        return builtin + extractor_cmds

    def get_command(self, ctx: click.Context, cmd_name: str) -> click.Command | None:
        # Builtin commands
        if cmd_name == "backends":
            return backends_cmd
        if cmd_name == "doctor":
            return doctor_cmd

        # Dynamic extractor commands
        module_name = cmd_name.replace("-", "_")
        registry = discover_extractors()
        if module_name in registry:
            return _make_extractor_command(module_name, registry[module_name])

        return None


def _make_extractor_command(
    name: str, extractor_cls: type
) -> click.Command:
    """Dynamically create a Click command for an extractor."""

    @click.command(name=name.replace("_", "-"))
    @click.option("-b", "--backend", required=True, help="Backend: ghidra, radare2")
    @click.option("-d", "--directory", required=True, type=click.Path(exists=True),
                  help="Path to binary directory")
    @click.option("-o", "--output", type=click.Path(), default=None,
                  help="Output directory")
    @click.option("-t", "--timeout", type=int, default=600,
                  help="Per-file timeout in seconds")
    @click.option("--pattern", default=None,
                  help="Glob pattern to filter files")
    @click.option("-g", "--ghidra-path", default=None, type=click.Path(),
                  help="Path to Ghidra analyzeHeadless")
    @click.pass_context
    def cmd(ctx, backend, directory, output, timeout, pattern, ghidra_path):
        """Extract features from binaries."""
        click.echo(f"Extractor: {name}, Backend: {backend}, Directory: {directory}")
        # Actual extraction logic will be wired in Phase 2

    cmd.help = extractor_cls.description.fget(extractor_cls) if hasattr(extractor_cls.description, 'fget') else "Extract features"
    return cmd


@click.group(cls=ExtractorGroup)
@click.version_option(version=reverse_tool.__version__, prog_name="reverse-tool")
@click.option("-v", "--verbose", count=True, help="Increase verbosity (-v, -vv)")
@click.option("-q", "--quiet", is_flag=True, help="Suppress output except results")
@click.pass_context
def cli(ctx: click.Context, verbose: int, quiet: bool) -> None:
    """ReverseTool - Binary analysis feature extraction framework."""
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose
    ctx.obj["quiet"] = quiet


@click.command("backends")
def backends_cmd() -> None:
    """List available backends and their status."""
    from rich.console import Console
    from rich.table import Table

    console = Console()
    table = Table(title="Available Backends")
    table.add_column("Backend", style="cyan")
    table.add_column("Status", style="green")

    # Always available
    table.add_row("null", "available (testing only)")

    # Check Ghidra
    import shutil
    ghidra_status = "available" if shutil.which("analyzeHeadless") else "not found"
    table.add_row("ghidra", ghidra_status)

    # Check Radare2
    r2_status = "available" if shutil.which("r2") else "not found"
    table.add_row("radare2", r2_status)

    console.print(table)


@click.command("doctor")
def doctor_cmd() -> None:
    """Check environment setup and dependencies."""
    from rich.console import Console

    console = Console()
    console.print(f"[bold]ReverseTool[/bold] v{reverse_tool.__version__}")
    console.print(f"Python:   {platform.python_version()}")
    console.print(f"Platform: {platform.platform()}")

    import shutil

    # Ghidra
    ghidra = shutil.which("analyzeHeadless")
    if ghidra:
        console.print(f"Ghidra:   [green]found[/green] ({ghidra})")
    else:
        console.print("Ghidra:   [yellow]not found[/yellow]")

    # Radare2
    r2 = shutil.which("r2")
    if r2:
        console.print(f"Radare2:  [green]found[/green] ({r2})")
    else:
        console.print("Radare2:  [yellow]not found[/yellow]")

    # Extractors
    registry = discover_extractors()
    console.print(f"Extractors: {len(registry)} registered")
    for name in sorted(registry):
        console.print(f"  - {name}")
```

- [ ] **Step 4: Run tests**

Run: `pytest tests/unit/test_cli.py -v`
Expected: All PASSED

- [ ] **Step 5: Verify CLI works end-to-end**

Run: `reverse-tool --help`
Expected: Shows help with version, options, and subcommands

Run: `reverse-tool --version`
Expected: `reverse-tool, version 0.1.0`

Run: `reverse-tool doctor`
Expected: Shows Python version, platform, backend status

Run: `reverse-tool backends`
Expected: Table with null/ghidra/radare2 status

- [ ] **Step 6: Commit**

```bash
git add src/reverse_tool/cli.py tests/unit/test_cli.py
git commit -m "feat: add Click CLI with auto-discovered extractor subcommands"
```

---

### Task 10: Linting and Type Checking

**Files:**
- Modify: all `src/` files (fix any lint issues)

- [ ] **Step 1: Run ruff check**

Run: `ruff check src/ tests/`
Expected: No errors (or fix any found)

- [ ] **Step 2: Run ruff format check**

Run: `ruff format --check src/ tests/`
Expected: No formatting issues (or run `ruff format src/ tests/` to fix)

- [ ] **Step 3: Run mypy**

Run: `mypy src/reverse_tool/`
Expected: No errors (or fix any found)

- [ ] **Step 4: Run full test suite**

Run: `pytest tests/ -v --tb=short`
Expected: All tests PASSED

- [ ] **Step 5: Commit any fixes**

```bash
git add -u
git commit -m "chore: fix lint and type checking issues"
```

---

### Task 11: Final Integration Verification

- [ ] **Step 1: Verify editable install**

Run: `pip install -e ".[dev]" && python -c "from reverse_tool.backends import BaseBackend; print('OK')"`
Expected: `OK`

- [ ] **Step 2: Verify full import chain**

Run:
```bash
python -c "
from reverse_tool import __version__
from reverse_tool.backends import BaseBackend, BackendInfo
from reverse_tool.backends.null import NullBackend, NullBackendConfig
from reverse_tool.extractors import BaseExtractor, ExtractResult
from reverse_tool.discovery import discover_extractors
from reverse_tool.engine import process_files, collect_files, TaskResult
from reverse_tool.config import load_config, Config
from reverse_tool.exceptions import ReverseToolError, BackendNotAvailable
print(f'All imports OK. Version: {__version__}')
"
```
Expected: `All imports OK. Version: 0.1.0`

- [ ] **Step 3: Run complete test suite with coverage**

Run: `pytest tests/ -v --cov=reverse_tool --cov-report=term-missing`
Expected: All PASSED, coverage > 85%

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "chore: phase 1 core framework complete"
```
