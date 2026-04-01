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


def write_functions_json(functions: dict[str, Any], output_path: Path) -> Path:
    """Write function disassembly as JSON."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(functions, f, indent=4)
    return output_path
