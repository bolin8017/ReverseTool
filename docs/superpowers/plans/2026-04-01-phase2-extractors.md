# Phase 2: Extractor Migration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Migrate opcode and function_call extractors from OpCodeReverseTool and FunctionCallReverseTool into the unified framework, with real Ghidra and Radare2 backends.

**Architecture:** GhidraBackend session = lightweight path container (each extractor runs its own subprocess). Radare2Backend session = active r2pipe connection. Extractors own their extraction logic and output writers.

**Tech Stack:** Python 3.12, r2pipe, subprocess, csv, json

**Spec:** `docs/superpowers/specs/2026-04-01-reverse-tool-unified-design.md`

**Depends on:** Phase 1 complete (BaseBackend, BaseExtractor, engine, CLI, NullBackend, 36 tests)

---

## File Map

| File | Responsibility |
|------|---------------|
| `src/reverse_tool/backends/ghidra.py` | GhidraBackend — validates Ghidra install, creates GhidraSession (paths container) |
| `src/reverse_tool/backends/radare2.py` | Radare2Backend — validates r2 install, opens r2pipe session |
| `src/reverse_tool/extractors/opcode/__init__.py` | OpcodeExtractor registration + CLI command |
| `src/reverse_tool/extractors/opcode/_ghidra.py` | Ghidra opcode extraction (subprocess + postScript) |
| `src/reverse_tool/extractors/opcode/_radare2.py` | Radare2 opcode extraction (r2pipe commands) |
| `src/reverse_tool/extractors/opcode/_writer.py` | CSV output writer |
| `src/reverse_tool/extractors/opcode/_scripts/ghidra_opcode.py` | Ghidra postScript for opcode extraction |
| `src/reverse_tool/extractors/opcode/_scripts/r2_timeout_check.sh` | Radare2 pre-flight timeout check |
| `src/reverse_tool/extractors/function_call/__init__.py` | FunctionCallExtractor registration + CLI command |
| `src/reverse_tool/extractors/function_call/_ghidra.py` | Ghidra function call extraction |
| `src/reverse_tool/extractors/function_call/_radare2.py` | Radare2 function call extraction |
| `src/reverse_tool/extractors/function_call/_writer.py` | DOT + JSON output writer |
| `src/reverse_tool/extractors/function_call/_scripts/ghidra_function_call.py` | Ghidra postScript for function call extraction |
| `tests/unit/test_opcode_extractor.py` | Opcode extractor unit tests (NullBackend) |
| `tests/unit/test_funcall_extractor.py` | Function call extractor unit tests (NullBackend) |
| `tests/unit/writers/test_csv_writer.py` | CSV writer tests |
| `tests/unit/writers/test_dot_writer.py` | DOT writer tests |
| `tests/unit/writers/test_json_writer.py` | JSON writer tests |

---

## Session Design

### GhidraSession (lightweight path container)

```python
@dataclass(frozen=True)
class GhidraSession:
    ghidra_path: Path        # Path to analyzeHeadless
    input_file: Path         # Binary being analyzed
    timeout: int             # Per-file timeout
    scripts_dir: Path        # Where Ghidra postScripts live
```

Each extractor runs its own `subprocess.run(analyzeHeadless ...)` call with its specific postScript. This matches Ghidra's execution model where each analyzeHeadless invocation is independent.

### Radare2Session (active connection)

```python
@dataclass
class Radare2Session:
    r2: Any                  # r2pipe.open() instance
    input_file: Path         # Binary being analyzed
```

Extractors send r2 commands via `session.r2.cmd()` / `session.r2.cmdj()`. Multiple extractors could share one session.

---

### Task 1: GhidraBackend + Radare2Backend

**Files:**
- Create: `src/reverse_tool/backends/ghidra.py`
- Create: `src/reverse_tool/backends/radare2.py`
- Modify: `src/reverse_tool/backends/__init__.py` (add lazy imports)
- Create: `tests/unit/test_ghidra_backend.py`
- Create: `tests/unit/test_radare2_backend.py`

- [ ] **Step 1: Write GhidraBackend**

`src/reverse_tool/backends/ghidra.py`:
```python
"""Ghidra reverse engineering backend."""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path

from reverse_tool.backends._base import BackendInfo, BaseBackend
from reverse_tool.exceptions import BackendNotAvailable


@dataclass(frozen=True)
class GhidraSession:
    """Lightweight session containing validated paths for Ghidra analysis."""

    ghidra_path: Path
    input_file: Path
    timeout: int


class GhidraBackend(BaseBackend["GhidraSession"]):
    """Ghidra-based binary analysis backend.

    Session is a lightweight path container. Each extractor runs its own
    analyzeHeadless subprocess with a specific postScript.
    """

    def __init__(self, ghidra_path: str | Path | None = None) -> None:
        self._ghidra_path = Path(ghidra_path) if ghidra_path else None

    @property
    def info(self) -> BackendInfo:
        return BackendInfo(name="ghidra", version="12.0.4")

    def validate_environment(self) -> None:
        if self._ghidra_path is None:
            # Try to find analyzeHeadless on PATH
            found = shutil.which("analyzeHeadless")
            if found:
                self._ghidra_path = Path(found)
            else:
                raise BackendNotAvailable(
                    "ghidra",
                    fix="Provide --ghidra-path or add analyzeHeadless to PATH",
                )
        if not self._ghidra_path.exists():
            raise BackendNotAvailable(
                "ghidra",
                fix=f"analyzeHeadless not found at {self._ghidra_path}",
            )

    def _open_session(self, input_file: Path, timeout: int) -> GhidraSession:
        return GhidraSession(
            ghidra_path=self._ghidra_path,
            input_file=input_file,
            timeout=timeout,
        )

    def _close_session(self, session: GhidraSession) -> None:
        pass  # No resources to release — each extractor manages its own temp files
```

- [ ] **Step 2: Write Radare2Backend**

`src/reverse_tool/backends/radare2.py`:
```python
"""Radare2 reverse engineering backend."""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from reverse_tool.backends._base import BackendInfo, BaseBackend
from reverse_tool.exceptions import BackendNotAvailable, BackendTimeout

_R2_TIMEOUT_SCRIPT = "_scripts/r2_timeout_check.sh"


@dataclass
class Radare2Session:
    """Active r2pipe session for binary analysis."""

    r2: Any  # r2pipe.open() instance
    input_file: Path


class Radare2Backend(BaseBackend["Radare2Session"]):
    """Radare2-based binary analysis backend.

    Session wraps an active r2pipe connection.
    """

    @property
    def info(self) -> BackendInfo:
        return BackendInfo(name="radare2", version="6.1.2")

    def validate_environment(self) -> None:
        if not shutil.which("r2"):
            raise BackendNotAvailable(
                "radare2",
                fix="Install Radare2: https://github.com/radareorg/radare2",
            )

    def _open_session(self, input_file: Path, timeout: int) -> Radare2Session:
        import r2pipe

        # Pre-flight timeout check
        if not self._check_timeout(input_file, timeout):
            raise BackendTimeout(str(input_file), timeout)

        r2 = r2pipe.open(str(input_file), flags=["-2"])
        return Radare2Session(r2=r2, input_file=input_file)

    def _close_session(self, session: Radare2Session) -> None:
        try:
            session.r2.quit()
        except Exception:
            pass

    @staticmethod
    def _check_timeout(input_file: Path, timeout: int) -> bool:
        """Run pre-flight timeout check."""
        # Find script relative to extractors that use it
        script_candidates = list(
            Path(__file__).parent.parent.glob(
                "extractors/*/_scripts/r2_timeout_check.sh"
            )
        )
        if not script_candidates:
            return True  # Skip check if script not found

        script = script_candidates[0]
        if not os.access(script, os.X_OK):
            return True

        try:
            result = subprocess.run(
                [str(script), str(input_file), str(timeout)],
                capture_output=True, text=True, check=True,
            )
            return result.stdout.strip() == "true"
        except subprocess.CalledProcessError:
            return False
```

- [ ] **Step 3: Update backends/__init__.py with lazy imports**

`src/reverse_tool/backends/__init__.py`:
```python
"""Backend infrastructure for ReverseTool."""

from reverse_tool.backends._base import BackendInfo, BaseBackend

__all__ = ["BackendInfo", "BaseBackend"]


def get_backend(name: str) -> type[BaseBackend]:
    """Get a backend class by name. Uses lazy imports."""
    if name == "ghidra":
        from reverse_tool.backends.ghidra import GhidraBackend
        return GhidraBackend
    elif name == "radare2":
        from reverse_tool.backends.radare2 import Radare2Backend
        return Radare2Backend
    elif name == "null":
        from reverse_tool.backends.null import NullBackend
        return NullBackend
    else:
        available = "ghidra, radare2, null"
        raise ValueError(f"Unknown backend {name!r}. Available: {available}")
```

- [ ] **Step 4: Write backend tests**

`tests/unit/test_ghidra_backend.py`:
```python
import pytest
from pathlib import Path

from reverse_tool.backends.ghidra import GhidraBackend, GhidraSession
from reverse_tool.exceptions import BackendNotAvailable

pytestmark = pytest.mark.unit


class TestGhidraBackend:
    def test_info(self):
        backend = GhidraBackend(ghidra_path="/fake/path")
        assert backend.info.name == "ghidra"

    def test_validate_missing_path_raises(self):
        backend = GhidraBackend(ghidra_path="/nonexistent/analyzeHeadless")
        with pytest.raises(BackendNotAvailable):
            backend.validate_environment()

    def test_session_returns_ghidra_session(self, tmp_path):
        # Create a fake analyzeHeadless
        fake_ghidra = tmp_path / "analyzeHeadless"
        fake_ghidra.write_text("#!/bin/bash\n")
        fake_ghidra.chmod(0o755)

        binary = tmp_path / "test.bin"
        binary.write_bytes(b"\x00")

        backend = GhidraBackend(ghidra_path=str(fake_ghidra))
        with backend.session(binary, timeout=60) as session:
            assert isinstance(session, GhidraSession)
            assert session.ghidra_path == fake_ghidra
            assert session.input_file == binary
            assert session.timeout == 60
```

`tests/unit/test_radare2_backend.py`:
```python
import pytest

from reverse_tool.backends.radare2 import Radare2Backend
from reverse_tool.backends import get_backend

pytestmark = pytest.mark.unit


class TestRadare2BackendUnit:
    def test_info(self):
        backend = Radare2Backend()
        assert backend.info.name == "radare2"

    def test_get_backend_returns_correct_classes(self):
        assert get_backend("null").__name__ == "NullBackend"
        assert get_backend("ghidra").__name__ == "GhidraBackend"
        assert get_backend("radare2").__name__ == "Radare2Backend"

    def test_get_backend_unknown_raises(self):
        with pytest.raises(ValueError, match="Unknown backend"):
            get_backend("ida")
```

- [ ] **Step 5: Run tests and commit**

Run: `pytest tests/unit/test_ghidra_backend.py tests/unit/test_radare2_backend.py -v`
Expected: All PASSED

```bash
git add src/reverse_tool/backends/ghidra.py src/reverse_tool/backends/radare2.py src/reverse_tool/backends/__init__.py tests/unit/test_ghidra_backend.py tests/unit/test_radare2_backend.py
git commit -m "feat: add GhidraBackend and Radare2Backend implementations"
```

---

### Task 2: Opcode Extractor + Writer

**Files:**
- Create: `src/reverse_tool/extractors/opcode/__init__.py`
- Create: `src/reverse_tool/extractors/opcode/_writer.py`
- Create: `src/reverse_tool/extractors/opcode/_ghidra.py`
- Create: `src/reverse_tool/extractors/opcode/_radare2.py`
- Create: `src/reverse_tool/extractors/opcode/_scripts/ghidra_opcode.py`
- Create: `src/reverse_tool/extractors/opcode/_scripts/r2_timeout_check.sh`
- Create: `tests/unit/writers/test_csv_writer.py`
- Create: `tests/unit/test_opcode_extractor.py`

- [ ] **Step 1: Write CSV writer**

`src/reverse_tool/extractors/opcode/_writer.py`:
```python
"""CSV writer for opcode extraction results."""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Any


def write_opcode_csv(
    opcodes: list[dict[str, Any]], output_path: Path
) -> Path:
    """Write extracted opcodes to a CSV file.

    Args:
        opcodes: List of dicts with keys: addr, opcode, section_name.
        output_path: Path to write CSV file.

    Returns:
        Path of the written file.
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f, fieldnames=["addr", "opcode", "section_name"]
        )
        writer.writeheader()
        writer.writerows(opcodes)
    return output_path
```

- [ ] **Step 2: Write CSV writer tests**

`tests/unit/writers/__init__.py`: (empty)

`tests/unit/writers/test_csv_writer.py`:
```python
import csv
import io
import pytest
from pathlib import Path

from reverse_tool.extractors.opcode._writer import write_opcode_csv

pytestmark = pytest.mark.unit


class TestCSVWriter:
    def test_writes_header_and_rows(self, tmp_path: Path):
        opcodes = [
            {"addr": 4194356, "opcode": "nop", "section_name": ".text"},
            {"addr": 4194360, "opcode": "mov", "section_name": ".text"},
        ]
        out = write_opcode_csv(opcodes, tmp_path / "out.csv")
        assert out.exists()

        with open(out, encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        assert len(rows) == 2
        assert rows[0]["opcode"] == "nop"
        assert rows[1]["addr"] == "4194360"

    def test_empty_opcodes_writes_header_only(self, tmp_path: Path):
        out = write_opcode_csv([], tmp_path / "empty.csv")
        with open(out, encoding="utf-8") as f:
            lines = f.read().strip().splitlines()
        assert len(lines) == 1
        assert "addr" in lines[0]

    def test_creates_parent_dirs(self, tmp_path: Path):
        out = write_opcode_csv(
            [{"addr": 1, "opcode": "ret", "section_name": ".text"}],
            tmp_path / "deep" / "nested" / "out.csv",
        )
        assert out.exists()
```

- [ ] **Step 3: Write Ghidra opcode extraction**

`src/reverse_tool/extractors/opcode/_ghidra.py`:
```python
"""Ghidra-specific opcode extraction logic."""

from __future__ import annotations

import csv
import logging
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

_GHIDRA_SCRIPT_NAME = "ghidra_opcode.py"
_TIMEOUT_EXIT_CODE = 124


def extract_opcodes_ghidra(
    session: Any,  # GhidraSession
    logger: logging.Logger,
) -> list[dict[str, Any]]:
    """Extract opcodes using Ghidra headless analyzer.

    Creates a temp project, runs analyzeHeadless with the opcode postScript,
    reads the resulting CSV, and cleans up.
    """
    scripts_dir = Path(__file__).parent / "_scripts"
    script_path = scripts_dir / _GHIDRA_SCRIPT_NAME
    file_name = session.input_file.name

    project_name = f"{file_name}_opcode_project"
    project_folder = Path(os.environ.get("TMPDIR", "/tmp")) / project_name
    temp_csv = project_folder / f"{file_name}.csv"

    project_folder.mkdir(parents=True, exist_ok=True)

    try:
        result = subprocess.run(
            [
                "timeout", "--kill-after=10", str(session.timeout),
                str(session.ghidra_path),
                str(project_folder), project_name,
                "-import", str(session.input_file),
                "-noanalysis",
                "-scriptPath", str(scripts_dir),
                "-postScript", str(script_path),
                str(temp_csv),
            ],
            capture_output=True,
            text=True,
        )

        if result.returncode == _TIMEOUT_EXIT_CODE:
            logger.error("%s: Ghidra analysis timed out after %ds", file_name, session.timeout)
            return []

        if result.returncode != 0:
            stderr_tail = (result.stderr[-500:] if result.stderr else "no output")
            logger.error("%s: Ghidra failed (exit %d): %s", file_name, result.returncode, stderr_tail)
            return []

        if not temp_csv.exists():
            logger.error("%s: Output CSV not found after Ghidra analysis", file_name)
            return []

        opcodes = []
        with open(temp_csv, encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                opcodes.append({
                    "addr": int(row["addr"]),
                    "opcode": row["opcode"],
                    "section_name": row["section_name"],
                })
        return opcodes

    except Exception as e:
        logger.exception("%s: Unexpected error: %s", file_name, e)
        return []
    finally:
        shutil.rmtree(project_folder, ignore_errors=True)
```

- [ ] **Step 4: Write Radare2 opcode extraction**

`src/reverse_tool/extractors/opcode/_radare2.py`:
```python
"""Radare2-specific opcode extraction logic."""

from __future__ import annotations

import logging
from typing import Any


def extract_opcodes_radare2(
    session: Any,  # Radare2Session
    logger: logging.Logger,
) -> list[dict[str, Any]]:
    """Extract opcodes using Radare2 via r2pipe.

    Iterates all sections, disassembles each, and collects opcode mnemonics.
    """
    file_name = session.input_file.name
    r2 = session.r2

    try:
        r2.cmd("e asm.flags.middle=0")
        sections = r2.cmdj("iSj")

        if not sections:
            logger.error(
                "%s: No sections found — file may be packed or damaged",
                file_name,
            )
            return []

        all_opcodes: list[dict[str, Any]] = []
        for section in sections:
            if section["size"] <= 0:
                continue
            instructions = r2.cmdj(
                f"pDj {section['size']} @{section['vaddr']}"
            ) or []
            for instr in instructions:
                opcode = instr.get("opcode", "")
                if opcode:
                    all_opcodes.append({
                        "addr": instr["offset"],
                        "opcode": opcode.split()[0],
                        "section_name": section["name"],
                    })

        return all_opcodes

    except Exception as e:
        logger.exception("%s: Unexpected error: %s", file_name, e)
        return []
```

- [ ] **Step 5: Write OpcodeExtractor**

`src/reverse_tool/extractors/opcode/__init__.py`:
```python
"""Opcode feature extractor."""

from __future__ import annotations

import logging
from pathlib import Path

from reverse_tool.extractors._base import BaseExtractor, ExtractResult
from reverse_tool.extractors.opcode._writer import write_opcode_csv


class OpcodeExtractor(BaseExtractor):
    """Extract opcode mnemonics from binary files.

    Outputs CSV with columns: addr, opcode, section_name.
    """

    @property
    def name(self) -> str:
        return "opcode"

    @property
    def description(self) -> str:
        return "Extract opcode sequences from binaries"

    @property
    def supported_backends(self) -> frozenset[str]:
        return frozenset({"ghidra", "radare2"})

    def extract(
        self, session, input_file: Path, logger: logging.Logger
    ) -> ExtractResult:
        backend_name = type(session).__name__

        if "Ghidra" in backend_name:
            from reverse_tool.extractors.opcode._ghidra import (
                extract_opcodes_ghidra,
            )
            opcodes = extract_opcodes_ghidra(session, logger)
        elif "Radare2" in backend_name or "Null" in backend_name:
            if "Null" in backend_name:
                opcodes = [
                    {"addr": 0, "opcode": op, "section_name": ".text"}
                    for ops in session.opcodes.values()
                    for op in ops
                ]
            else:
                from reverse_tool.extractors.opcode._radare2 import (
                    extract_opcodes_radare2,
                )
                opcodes = extract_opcodes_radare2(session, logger)
        else:
            opcodes = []

        return ExtractResult(
            extractor_name=self.name,
            input_file=input_file,
            data={"opcodes": opcodes},
            metadata={"count": len(opcodes)},
        )

    def write_output(
        self, result: ExtractResult, output_dir: Path
    ) -> list[Path]:
        csv_path = output_dir / f"{result.input_file.stem}.csv"
        write_opcode_csv(result.data["opcodes"], csv_path)
        return [csv_path]
```

- [ ] **Step 6: Copy Ghidra postScript and r2 timeout check**

`src/reverse_tool/extractors/opcode/_scripts/ghidra_opcode.py`:
(Copy from OpCodeReverseTool/scripts/ghidra_opcode_script.py — exact content)

`src/reverse_tool/extractors/opcode/_scripts/r2_timeout_check.sh`:
(Copy from OpCodeReverseTool/scripts/r2_timeout_check.sh — exact content, chmod +x)

- [ ] **Step 7: Write opcode extractor tests**

`tests/unit/test_opcode_extractor.py`:
```python
import logging
import pytest
from pathlib import Path

from reverse_tool.backends.null import NullBackend, NullBackendConfig, NullSession
from reverse_tool.extractors.opcode import OpcodeExtractor

pytestmark = pytest.mark.unit


@pytest.fixture
def opcode_extractor():
    return OpcodeExtractor()


class TestOpcodeExtractor:
    def test_name_and_description(self, opcode_extractor):
        assert opcode_extractor.name == "opcode"
        assert "opcode" in opcode_extractor.description.lower()

    def test_supported_backends(self, opcode_extractor):
        assert "ghidra" in opcode_extractor.supported_backends
        assert "radare2" in opcode_extractor.supported_backends

    def test_extract_with_null_backend(self, opcode_extractor, tmp_path):
        config = NullBackendConfig(
            opcodes={"main": ["push", "mov", "ret"], "exit": ["mov", "syscall"]},
        )
        backend = NullBackend(config)
        binary = tmp_path / "test_bin"
        binary.write_bytes(b"\x00")
        log = logging.getLogger("test")

        with backend.session(binary) as session:
            result = opcode_extractor.extract(session, binary, log)

        assert result.extractor_name == "opcode"
        assert len(result.data["opcodes"]) == 5  # 3 + 2
        assert result.data["opcodes"][0]["opcode"] == "push"

    def test_write_output_creates_csv(self, opcode_extractor, tmp_path):
        from reverse_tool.extractors._base import ExtractResult

        result = ExtractResult(
            extractor_name="opcode",
            input_file=Path("test_bin"),
            data={"opcodes": [
                {"addr": 1, "opcode": "push", "section_name": ".text"},
                {"addr": 2, "opcode": "ret", "section_name": ".text"},
            ]},
        )
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        written = opcode_extractor.write_output(result, output_dir)
        assert len(written) == 1
        assert written[0].suffix == ".csv"
        assert written[0].exists()

    def test_auto_registered(self):
        from reverse_tool.discovery import discover_extractors
        registry = discover_extractors()
        assert "opcode" in registry
```

- [ ] **Step 8: Run tests and commit**

Run: `pytest tests/unit/test_opcode_extractor.py tests/unit/writers/test_csv_writer.py -v`
Expected: All PASSED

```bash
git add src/reverse_tool/extractors/opcode/ tests/unit/test_opcode_extractor.py tests/unit/writers/
git commit -m "feat: add opcode extractor with Ghidra and Radare2 support"
```

---

### Task 3: Function Call Extractor + Writer

**Files:**
- Create: `src/reverse_tool/extractors/function_call/__init__.py`
- Create: `src/reverse_tool/extractors/function_call/_writer.py`
- Create: `src/reverse_tool/extractors/function_call/_ghidra.py`
- Create: `src/reverse_tool/extractors/function_call/_radare2.py`
- Create: `src/reverse_tool/extractors/function_call/_scripts/ghidra_function_call.py`
- Create: `tests/unit/writers/test_dot_writer.py`
- Create: `tests/unit/writers/test_json_writer.py`
- Create: `tests/unit/test_funcall_extractor.py`

- [ ] **Step 1: Write DOT + JSON writer**

`src/reverse_tool/extractors/function_call/_writer.py`:
```python
"""DOT and JSON writers for function call extraction results."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def write_dot(dot_content: str, output_path: Path) -> Path:
    """Write DOT format call graph."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(dot_content, encoding="utf-8")
    return output_path


def write_functions_json(
    functions: dict[str, Any], output_path: Path
) -> Path:
    """Write function disassembly as JSON."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(functions, f, indent=4)
    return output_path
```

- [ ] **Step 2: Write writer tests**

`tests/unit/writers/test_dot_writer.py`:
```python
import pytest
from pathlib import Path

from reverse_tool.extractors.function_call._writer import write_dot

pytestmark = pytest.mark.unit


class TestDOTWriter:
    def test_writes_dot_content(self, tmp_path):
        content = 'digraph code {\n  "0x1000" -> "0x2000";\n}'
        out = write_dot(content, tmp_path / "graph.dot")
        assert out.exists()
        assert out.read_text() == content

    def test_creates_parent_dirs(self, tmp_path):
        out = write_dot("digraph {}", tmp_path / "deep" / "graph.dot")
        assert out.exists()
```

`tests/unit/writers/test_json_writer.py`:
```python
import json
import pytest
from pathlib import Path

from reverse_tool.extractors.function_call._writer import write_functions_json

pytestmark = pytest.mark.unit


class TestJSONWriter:
    def test_writes_valid_json(self, tmp_path):
        functions = {
            "0x1000": {"function_name": "main", "instructions": ["push", "ret"]},
        }
        out = write_functions_json(functions, tmp_path / "funcs.json")
        assert out.exists()
        parsed = json.loads(out.read_text())
        assert parsed["0x1000"]["function_name"] == "main"

    def test_round_trip(self, tmp_path):
        data = {"0x1": {"name": "a", "calls": ["b"]}}
        out = write_functions_json(data, tmp_path / "rt.json")
        assert json.loads(out.read_text()) == data
```

- [ ] **Step 3: Write Ghidra function call extraction**

`src/reverse_tool/extractors/function_call/_ghidra.py`:
```python
"""Ghidra-specific function call extraction logic."""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

_GHIDRA_SCRIPT_NAME = "ghidra_function_call.py"
_TIMEOUT_EXIT_CODE = 124


def extract_function_calls_ghidra(
    session: Any,  # GhidraSession
    logger: logging.Logger,
) -> dict[str, Any]:
    """Extract function call graph and disassembly using Ghidra.

    Returns dict with 'dot_content' and 'functions' keys, or empty dict on failure.
    """
    scripts_dir = Path(__file__).parent / "_scripts"
    script_path = scripts_dir / _GHIDRA_SCRIPT_NAME
    file_name = session.input_file.name

    project_name = f"{file_name}_funcall_project"
    project_folder = Path(os.environ.get("TMPDIR", "/tmp")) / project_name

    project_folder.mkdir(parents=True, exist_ok=True)

    try:
        result = subprocess.run(
            [
                "timeout", "--kill-after=10", str(session.timeout),
                str(session.ghidra_path),
                str(project_folder), project_name,
                "-import", str(session.input_file),
                "-scriptPath", str(scripts_dir),
                "-postScript", _GHIDRA_SCRIPT_NAME,
                str(project_folder),
            ],
            capture_output=True,
            text=True,
        )

        if result.returncode == _TIMEOUT_EXIT_CODE:
            logger.error("%s: Ghidra analysis timed out after %ds", file_name, session.timeout)
            return {}

        if result.returncode != 0:
            stderr_tail = (result.stderr[-500:] if result.stderr else "no output")
            logger.error("%s: Ghidra failed (exit %d): %s", file_name, result.returncode, stderr_tail)
            return {}

        dot_path = project_folder / f"{file_name}.dot"
        json_path = project_folder / f"{file_name}.json"

        if not dot_path.exists() or not json_path.exists():
            logger.error("%s: Output files not found after Ghidra analysis", file_name)
            return {}

        dot_content = dot_path.read_text(encoding="utf-8")
        with open(json_path, encoding="utf-8") as f:
            functions = json.load(f)

        return {"dot_content": dot_content, "functions": functions}

    except Exception as e:
        logger.exception("%s: Unexpected error: %s", file_name, e)
        return {}
    finally:
        shutil.rmtree(project_folder, ignore_errors=True)
```

- [ ] **Step 4: Write Radare2 function call extraction**

`src/reverse_tool/extractors/function_call/_radare2.py`:
```python
"""Radare2-specific function call extraction logic."""

from __future__ import annotations

import logging
import re
from typing import Any


def extract_function_calls_radare2(
    session: Any,  # Radare2Session
    logger: logging.Logger,
) -> dict[str, Any]:
    """Extract function call graph and disassembly using Radare2.

    Returns dict with 'dot_content' and 'functions' keys, or empty dict on failure.
    """
    file_name = session.input_file.name
    r2 = session.r2

    try:
        r2.cmd("aaa")
        raw_graph = r2.cmd("agCd")

        if not raw_graph:
            logger.error("%s: No functions found", file_name)
            return {}

        function_call_graph = ["digraph code {"]
        functions_info: dict[str, Any] = {}
        pattern = r'"(0x[0-9a-fA-F]+)" \[label="([^"]+)"\];'

        lines = raw_graph.split("\n")
        # agCd output: 6 header lines, content, closing "}" and empty line
        for line in lines[6:-2]:
            line = re.sub(r' URL="[^"]*"', "", line)
            line = re.sub(r" \[.*color=[^\]]*\]", "", line)
            function_call_graph.append(line)

            match = re.search(pattern, line)
            if not match:
                continue

            address, name = match.groups()
            functions_info[address] = {
                "function_name": name,
                "instructions": [],
            }

            try:
                instructions = r2.cmdj(f"pdfj @ {address}")["ops"]
                for inst in instructions:
                    disasm = inst.get("disasm", "invalid")
                    functions_info[address]["instructions"].append(disasm)
            except Exception as e:
                logger.error(
                    "%s: Error extracting instructions at %s: %s",
                    file_name, address, e,
                )
                functions_info[address]["instructions"].append("error")

        function_call_graph.append("}")
        dot_content = "\n".join(function_call_graph)

        return {"dot_content": dot_content, "functions": functions_info}

    except Exception as e:
        logger.exception("%s: Unexpected error: %s", file_name, e)
        return {}
```

- [ ] **Step 5: Write FunctionCallExtractor**

`src/reverse_tool/extractors/function_call/__init__.py`:
```python
"""Function call feature extractor."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from reverse_tool.extractors._base import BaseExtractor, ExtractResult
from reverse_tool.extractors.function_call._writer import (
    write_dot,
    write_functions_json,
)


class FunctionCallExtractor(BaseExtractor):
    """Extract function call graphs and per-function disassembly.

    Outputs DOT (call graph) and JSON (function disassembly).
    """

    @property
    def name(self) -> str:
        return "function_call"

    @property
    def description(self) -> str:
        return "Extract function call graphs from binaries"

    @property
    def supported_backends(self) -> frozenset[str]:
        return frozenset({"ghidra", "radare2"})

    def extract(
        self, session: Any, input_file: Path, logger: logging.Logger
    ) -> ExtractResult:
        backend_name = type(session).__name__

        if "Ghidra" in backend_name:
            from reverse_tool.extractors.function_call._ghidra import (
                extract_function_calls_ghidra,
            )
            features = extract_function_calls_ghidra(session, logger)
        elif "Radare2" in backend_name:
            from reverse_tool.extractors.function_call._radare2 import (
                extract_function_calls_radare2,
            )
            features = extract_function_calls_radare2(session, logger)
        elif "Null" in backend_name:
            # Build from NullSession data
            dot_lines = ["digraph code {"]
            for addr, info in session.functions.items():
                dot_lines.append(f'  "{addr}" [label="{addr}"];')
                for callee in info.get("calls", []):
                    dot_lines.append(f'  "{addr}" -> "{callee}";')
            dot_lines.append("}")
            features = {
                "dot_content": "\n".join(dot_lines),
                "functions": session.functions,
            }
        else:
            features = {}

        return ExtractResult(
            extractor_name=self.name,
            input_file=input_file,
            data=features,
            metadata={"function_count": len(features.get("functions", {}))},
        )

    def write_output(
        self, result: ExtractResult, output_dir: Path
    ) -> list[Path]:
        written = []
        stem = result.input_file.stem

        if "dot_content" in result.data:
            dot_path = write_dot(
                result.data["dot_content"], output_dir / f"{stem}.dot"
            )
            written.append(dot_path)

        if "functions" in result.data:
            json_path = write_functions_json(
                result.data["functions"], output_dir / f"{stem}.json"
            )
            written.append(json_path)

        return written
```

- [ ] **Step 6: Copy Ghidra postScript**

`src/reverse_tool/extractors/function_call/_scripts/ghidra_function_call.py`:
(Copy from FunctionCallReverseTool/function_call_tool/scripts/ghidra_function_script.py — exact content)

- [ ] **Step 7: Write function call extractor tests**

`tests/unit/test_funcall_extractor.py`:
```python
import json
import logging
import pytest
from pathlib import Path

from reverse_tool.backends.null import NullBackend, NullBackendConfig
from reverse_tool.extractors.function_call import FunctionCallExtractor

pytestmark = pytest.mark.unit


@pytest.fixture
def funcall_extractor():
    return FunctionCallExtractor()


class TestFunctionCallExtractor:
    def test_name_and_description(self, funcall_extractor):
        assert funcall_extractor.name == "function_call"
        assert "function" in funcall_extractor.description.lower()

    def test_supported_backends(self, funcall_extractor):
        assert "ghidra" in funcall_extractor.supported_backends
        assert "radare2" in funcall_extractor.supported_backends

    def test_extract_with_null_backend(self, funcall_extractor, tmp_path):
        config = NullBackendConfig(
            functions={
                "main": {"addr": 0x1000, "size": 42, "calls": ["printf"]},
                "printf": {"addr": 0x2000, "size": 10, "calls": []},
            },
        )
        backend = NullBackend(config)
        binary = tmp_path / "test_bin"
        binary.write_bytes(b"\x00")
        log = logging.getLogger("test")

        with backend.session(binary) as session:
            result = funcall_extractor.extract(session, binary, log)

        assert result.extractor_name == "function_call"
        assert "digraph" in result.data["dot_content"]
        assert "main" in result.data["functions"]

    def test_write_output_creates_dot_and_json(self, funcall_extractor, tmp_path):
        from reverse_tool.extractors._base import ExtractResult

        result = ExtractResult(
            extractor_name="function_call",
            input_file=Path("test_bin"),
            data={
                "dot_content": "digraph code {}",
                "functions": {"0x1000": {"function_name": "main"}},
            },
        )
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        written = funcall_extractor.write_output(result, output_dir)
        assert len(written) == 2
        extensions = {p.suffix for p in written}
        assert ".dot" in extensions
        assert ".json" in extensions

    def test_auto_registered(self):
        from reverse_tool.discovery import discover_extractors
        registry = discover_extractors()
        assert "function_call" in registry
```

- [ ] **Step 8: Run tests and commit**

Run: `pytest tests/unit/test_funcall_extractor.py tests/unit/writers/ -v`
Expected: All PASSED

```bash
git add src/reverse_tool/extractors/function_call/ tests/unit/test_funcall_extractor.py tests/unit/writers/test_dot_writer.py tests/unit/writers/test_json_writer.py
git commit -m "feat: add function call extractor with Ghidra and Radare2 support"
```

---

### Task 4: Wire CLI to Engine + Full Test Suite

**Files:**
- Modify: `src/reverse_tool/cli.py` (wire extractor commands to engine)
- Create: `tests/unit/test_cli_integration.py`

- [ ] **Step 1: Update `_make_extractor_command` in cli.py**

Replace the placeholder `_make_extractor_command` with real engine integration:

```python
def _make_extractor_command(
    name: str, extractor_cls: type
) -> click.Command:
    """Dynamically create a Click command for an extractor."""

    @click.command(name=name.replace("_", "-"))
    @click.option("-b", "--backend", required=True,
                  type=click.Choice(["ghidra", "radare2"]),
                  help="Analysis backend")
    @click.option("-d", "--directory", required=True,
                  type=click.Path(exists=True), help="Binary directory")
    @click.option("-o", "--output", type=click.Path(), default=None,
                  help="Output directory")
    @click.option("-t", "--timeout", type=int, default=600,
                  help="Per-file timeout (seconds)")
    @click.option("--pattern", default=None, help="Glob pattern")
    @click.option("-g", "--ghidra-path", default=None,
                  type=click.Path(), help="Path to analyzeHeadless")
    @click.pass_context
    def cmd(ctx, backend, directory, output, timeout, pattern, ghidra_path):
        from pathlib import Path
        from reverse_tool.backends import get_backend
        from reverse_tool.engine import collect_files, process_files

        directory = Path(directory)
        output_dir = Path(output) if output else directory.parent / f"{directory.name}_output"
        output_dir.mkdir(parents=True, exist_ok=True)

        backend_cls = get_backend(backend)
        # Build backend config
        if backend == "ghidra":
            backend_obj = backend_cls(ghidra_path=ghidra_path)
        else:
            backend_obj = backend_cls()

        backend_obj.validate_environment()

        files = collect_files(directory, pattern=pattern)
        if not files:
            click.echo(f"No matching files found in {directory}")
            return

        click.echo(f"Processing {len(files)} files with {name} ({backend})")

        succeeded = 0
        failed = 0
        for result in process_files(
            files=files,
            backend_cls=backend_cls,
            extractor_cls=extractor_cls,
            output_dir=output_dir,
            backend_config=ghidra_path if backend == "ghidra" else None,
            max_workers=1,  # Default to sequential for safety
            timeout=timeout,
        ):
            if result.success:
                succeeded += 1
            else:
                failed += 1

        click.echo(f"Done: {succeeded} succeeded, {failed} failed")

    desc = getattr(extractor_cls, 'description', None)
    if desc and hasattr(desc, 'fget'):
        cmd.help = desc.fget(extractor_cls)
    return cmd
```

- [ ] **Step 2: Run full test suite**

Run: `pytest tests/ -v --tb=short`
Expected: All PASSED

- [ ] **Step 3: Run lint and type check**

Run: `ruff check src/ tests/ && ruff format --check src/ tests/ && mypy src/reverse_tool/`
Fix any issues.

- [ ] **Step 4: Verify CLI shows extractors**

Run: `reverse-tool --help`
Expected: Shows `opcode` and `function-call` as subcommands

Run: `reverse-tool opcode --help`
Expected: Shows -b, -d, -o, -t, --pattern, -g options

- [ ] **Step 5: Commit**

```bash
git add -u
git commit -m "feat: wire CLI extractor commands to processing engine"
```

---

### Task 5: Final Verification

- [ ] **Step 1: Run complete test suite with coverage**

Run: `pytest tests/ -v --cov=reverse_tool --cov-report=term-missing`
Expected: All PASSED, coverage > 80%

- [ ] **Step 2: Verify all imports**

```bash
python -c "
from reverse_tool.backends.ghidra import GhidraBackend, GhidraSession
from reverse_tool.backends.radare2 import Radare2Backend, Radare2Session
from reverse_tool.backends import get_backend
from reverse_tool.extractors.opcode import OpcodeExtractor
from reverse_tool.extractors.function_call import FunctionCallExtractor
from reverse_tool.discovery import discover_extractors
registry = discover_extractors()
print(f'Backends: ghidra, radare2, null')
print(f'Extractors: {list(registry.keys())}')
print('All Phase 2 imports OK')
"
```

- [ ] **Step 3: Commit**

```bash
git add -A && git commit -m "chore: phase 2 extractors complete"
```
