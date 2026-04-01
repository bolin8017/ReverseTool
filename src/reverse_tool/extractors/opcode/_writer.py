"""Writers for opcode extraction results."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from reverse_tool.extractors._utils import build_output_metadata


def write_opcode_jsonl(
    opcodes: list[dict[str, Any]],
    output_path: Path,
    *,
    input_file: Path | None = None,
    backend: str = "",
    sections: list[dict[str, Any]] | None = None,
    binary_info: dict[str, Any] | None = None,
) -> Path:
    """Write opcodes as a single JSON record per binary (JSONL-compatible)."""
    output_path.parent.mkdir(parents=True, exist_ok=True)

    meta = build_output_metadata(
        extractor="opcode",
        backend=backend,
        input_file=input_file,
        instruction_count=len(opcodes),
    )
    if binary_info:
        meta["binary_info"] = binary_info

    record: dict[str, Any] = {"meta": meta, "opcodes": opcodes}
    if sections:
        record["sections"] = sections

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(record, f, separators=(",", ":"))
        f.write("\n")

    return output_path
