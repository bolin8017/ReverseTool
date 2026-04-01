"""CSV writer for opcode extraction results."""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Any


def write_opcode_csv(opcodes: list[dict[str, Any]], output_path: Path) -> Path:
    """Write extracted opcodes to a CSV file.

    Args:
        opcodes: List of dicts with keys: addr, opcode, section_name.
        output_path: Path to write CSV file.

    Returns:
        Path of the written file.
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["addr", "opcode", "section_name"])
        writer.writeheader()
        writer.writerows(opcodes)
    return output_path
