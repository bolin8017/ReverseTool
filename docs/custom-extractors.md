# Custom Extractors

This guide walks through adding a new feature extractor to ReverseTool. The plugin architecture makes this straightforward -- a minimal extractor requires ~50 lines of code and auto-registers with the CLI.

## How Auto-Discovery Works

ReverseTool uses `__init_subclass__` for zero-configuration registration:

1. You subclass `BaseExtractor`
2. On class creation, `__init_subclass__` fires and calls `_register_extractor()`
3. The extractor is added to the global registry
4. `discover_extractors()` imports all packages under `reverse_tool.extractors` via `pkgutil.walk_packages()`
5. Your extractor appears as a new CLI subcommand automatically

No decorators, no entry points, no configuration files.

## Directory Structure

Create a new package under `src/reverse_tool/extractors/`:

```
src/reverse_tool/extractors/my_feature/
    __init__.py          # MyFeatureExtractor class (entry point)
    _ghidra.py           # Ghidra-specific extraction logic
    _radare2.py          # Radare2-specific extraction logic
    _idapro.py           # IDA Pro-specific extraction logic (optional)
    _writer.py           # Output writer
    _scripts/            # (optional) Backend-specific scripts
        ghidra_my_feature.py    # Ghidra/PyGhidra postScript
        idapro_my_feature.py    # IDAPython script
```

## BaseExtractor API Reference

```python
from reverse_tool.extractors._base import BaseExtractor, ExtractResult

class BaseExtractor(ABC, Generic[T_Session]):
    """Abstract base class for all extractors."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique identifier. Used as CLI subcommand name.
        Convention: snake_case (e.g., 'my_feature').
        CLI converts to kebab-case (e.g., 'my-feature')."""
        ...

    @property
    @abstractmethod
    def description(self) -> str:
        """Short human-readable description. Shown in --help."""
        ...

    @property
    @abstractmethod
    def supported_backends(self) -> frozenset[str]:
        """Set of backend names: {'ghidra', 'radare2', 'idapro'}."""
        ...

    @abstractmethod
    def extract(
        self,
        session: T_Session,
        input_file: Path,
        logger: logging.Logger,
    ) -> ExtractResult:
        """Extract features from a backend session.
        Returns an ExtractResult with the extracted data."""
        ...

    @abstractmethod
    def write_output(
        self, result: ExtractResult, output_dir: Path
    ) -> list[Path]:
        """Write results to disk. Returns list of created file paths."""
        ...
```

### ExtractResult

```python
@dataclass(frozen=True)
class ExtractResult:
    extractor_name: str          # Must match your extractor's name
    input_file: Path             # The binary that was analyzed
    data: dict[str, Any]         # Your extracted data
    metadata: dict[str, Any]     # Optional metadata (counts, timing, etc.)
```

## Step-by-Step Implementation

### Step 1: Create the Extractor Class

```python
# src/reverse_tool/extractors/my_feature/__init__.py
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from reverse_tool.extractors._base import BaseExtractor, ExtractResult
from reverse_tool.extractors.my_feature._writer import write_my_feature


class MyFeatureExtractor(BaseExtractor):
    """Extract my feature from binary files."""

    @property
    def name(self) -> str:
        return "my_feature"

    @property
    def description(self) -> str:
        return "Extract my feature from binaries"

    @property
    def supported_backends(self) -> frozenset[str]:
        return frozenset({"ghidra", "radare2", "idapro"})

    def extract(
        self, session: Any, input_file: Path, logger: logging.Logger
    ) -> ExtractResult:
        from reverse_tool.backends.ghidra import GhidraSession
        from reverse_tool.backends.idapro import IdaproSession
        from reverse_tool.backends.null import NullSession
        from reverse_tool.backends.radare2 import Radare2Session
        from reverse_tool.exceptions import IncompatibleBackendError

        if isinstance(session, GhidraSession):
            from reverse_tool.extractors.my_feature._ghidra import (
                extract_my_feature_ghidra,
            )
            data = extract_my_feature_ghidra(session, logger)
        elif isinstance(session, Radare2Session):
            from reverse_tool.extractors.my_feature._radare2 import (
                extract_my_feature_radare2,
            )
            data = extract_my_feature_radare2(session, logger)
        elif isinstance(session, IdaproSession):
            from reverse_tool.extractors.my_feature._idapro import (
                extract_my_feature_idapro,
            )
            data = extract_my_feature_idapro(session, logger)
        elif isinstance(session, NullSession):
            data = {"features": []}  # Test stub
        else:
            raise IncompatibleBackendError(
                "my_feature",
                type(session).__name__,
                frozenset({"ghidra", "radare2", "idapro"}),
            )

        backend_name = type(session).__name__.replace("Session", "").lower()
        data["backend"] = backend_name

        return ExtractResult(
            extractor_name=self.name,
            input_file=input_file,
            data=data,
            metadata={"feature_count": len(data.get("features", []))},
        )

    def write_output(self, result: ExtractResult, output_dir: Path) -> list[Path]:
        stem = result.input_file.stem
        output_path = write_my_feature(
            result.data,
            output_dir / f"{stem}.json",
            input_file=result.input_file,
            backend=result.data.get("backend", ""),
        )
        return [output_path]
```

### Step 2: Implement Backend-Specific Logic

#### Radare2

```python
# src/reverse_tool/extractors/my_feature/_radare2.py
from __future__ import annotations

import logging
from typing import Any

from reverse_tool.backends.radare2 import Radare2Session


def extract_my_feature_radare2(
    session: Radare2Session, logger: logging.Logger
) -> dict[str, Any]:
    """Extract features using r2pipe commands."""
    r2 = session.r2

    # Run analysis
    r2.cmd("aa")

    # Use r2.cmdj() for JSON output
    info = r2.cmdj("ij") or {}
    functions = r2.cmdj("aflj") or []

    features = []
    for func in functions:
        features.append({
            "name": func.get("name", ""),
            "address": hex(func.get("offset", 0)),
            "size": func.get("size", 0),
        })

    logger.info("Extracted %d features via Radare2", len(features))
    return {"features": features}
```

#### Ghidra

```python
# src/reverse_tool/extractors/my_feature/_ghidra.py
from __future__ import annotations

import json
import logging
import shutil
from pathlib import Path
from typing import Any

from reverse_tool.backends.ghidra import GhidraSession
from reverse_tool.extractors._ghidra_runner import run_ghidra_script


def extract_my_feature_ghidra(
    session: GhidraSession, logger: logging.Logger
) -> dict[str, Any]:
    """Extract features via PyGhidra subprocess."""
    script_path = Path(__file__).parent / "_scripts" / "ghidra_my_feature.py"

    project_folder, output_path = run_ghidra_script(
        session=session,
        script_path=script_path,
        project_name="my_feature",
        output_name="my_feature.json",
        logger=logger,
    )

    try:
        with open(output_path, encoding="utf-8") as f:
            data = json.load(f)
    finally:
        shutil.rmtree(project_folder, ignore_errors=True)

    return data
```

#### IDA Pro

```python
# src/reverse_tool/extractors/my_feature/_idapro.py
from __future__ import annotations

import json
import logging
import shutil
from pathlib import Path
from typing import Any

from reverse_tool.backends.idapro import IdaproSession
from reverse_tool.extractors._idapro_runner import run_ida_script


def extract_my_feature_idapro(
    session: IdaproSession, logger: logging.Logger
) -> dict[str, Any]:
    """Extract features via IDA Pro subprocess."""
    script_path = Path(__file__).parent / "_scripts" / "idapro_my_feature.py"

    temp_dir, output_path = run_ida_script(
        session=session,
        script_path=script_path,
        output_name="my_feature.json",
        logger=logger,
    )

    try:
        with open(output_path, encoding="utf-8") as f:
            data = json.load(f)
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

    return data
```

### Step 3: Implement the Writer

```python
# src/reverse_tool/extractors/my_feature/_writer.py
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from reverse_tool.extractors._utils import build_output_metadata


def write_my_feature(
    data: dict[str, Any],
    output_path: Path,
    *,
    input_file: Path | None = None,
    backend: str = "",
) -> Path:
    """Write extracted features as JSON."""
    output_path.parent.mkdir(parents=True, exist_ok=True)

    meta = build_output_metadata(
        extractor="my_feature",
        backend=backend,
        input_file=input_file,
        feature_count=len(data.get("features", [])),
    )

    record = {"meta": meta, "features": data.get("features", [])}

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(record, f, indent=2)

    return output_path
```

### Step 4: Write Tests with NullBackend

The `NullBackend` is a programmable test backend that requires no external tools.

```python
# tests/unit/test_my_feature.py
from pathlib import Path

from reverse_tool.backends.null import NullBackend, NullBackendConfig
from reverse_tool.extractors.my_feature import MyFeatureExtractor


def test_my_feature_extract(tmp_path: Path) -> None:
    """Test extraction with NullBackend."""
    # Create a dummy binary
    binary = tmp_path / "test_binary"
    binary.write_bytes(b"\x00" * 100)

    # Configure NullBackend
    backend = NullBackend(NullBackendConfig())
    extractor = MyFeatureExtractor()

    with backend.session(binary) as session:
        result = extractor.extract(session, binary, __import__("logging").getLogger())

    assert result.extractor_name == "my_feature"
    assert result.input_file == binary


def test_my_feature_write_output(tmp_path: Path) -> None:
    """Test output writing."""
    from reverse_tool.extractors._base import ExtractResult

    result = ExtractResult(
        extractor_name="my_feature",
        input_file=tmp_path / "test_binary",
        data={"features": [{"name": "main"}], "backend": "null"},
    )

    extractor = MyFeatureExtractor()
    output_dir = tmp_path / "output"
    paths = extractor.write_output(result, output_dir)

    assert len(paths) == 1
    assert paths[0].exists()
```

Run tests:

```bash
.venv/bin/python -m pytest tests/unit/test_my_feature.py -v
```

### Step 5: Verify Registration

After adding the files, verify your extractor is registered:

```bash
reverse-tool backends        # Should list available backends
reverse-tool my-feature --help  # Should show your extractor's help
reverse-tool doctor          # Should list your extractor
```

The CLI automatically converts `my_feature` (Python) to `my-feature` (CLI).

## Tips

- **Start with one backend**: Implement Radare2 first (easiest to test), then add Ghidra and IDA Pro
- **Use `build_output_metadata()`**: The shared utility in `_utils.py` handles file hashing and standard metadata fields
- **Use the shared runners**: `_ghidra_runner.run_ghidra_script()` and `_idapro_runner.run_ida_script()` handle subprocess management, timeout, and error handling
- **Test with NullBackend**: All unit tests should use `NullBackend` so CI runs without any real backends installed
- **Follow the naming convention**: Extractor name in snake_case, CLI command in kebab-case
