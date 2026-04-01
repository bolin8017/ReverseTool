"""Writers for function call extraction results."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from reverse_tool.extractors._utils import build_output_metadata


def write_function_call_json(
    functions: dict[str, Any],
    dot_content: str,
    output_path: Path,
    *,
    input_file: Path | None = None,
    backend: str = "",
) -> Path:
    """Write unified function call JSON with function data and metadata."""
    output_path.parent.mkdir(parents=True, exist_ok=True)

    meta = build_output_metadata(
        extractor="function_call",
        backend=backend,
        input_file=input_file,
        function_count=len(functions),
    )

    nodes = []
    for addr, info in functions.items():
        node = {
            "id": addr,
            "label": info.get("function_name", addr),
            "instruction_count": len(info.get("instructions", [])),
            "instructions": info.get("instructions", []),
        }
        if "is_external" in info:
            node["is_external"] = info["is_external"]
        nodes.append(node)

    record = {
        "meta": meta,
        "call_graph": {
            "directed": True,
            "nodes": nodes,
            "functions": functions,
        },
        "dot": dot_content,
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(record, f, indent=2)

    return output_path
