"""Radare2-specific function call extraction logic."""

from __future__ import annotations

import logging
import re
from typing import Any

# DOT header/footer lines to skip (content-based, not index-based)
_DOT_SKIP_PREFIXES = (
    "digraph",
    "rankdir",
    "outputorder",
    "graph ",
    "node ",
    "edge [",
    "}",
)


def extract_function_calls_radare2(
    session: Any,
    logger: logging.Logger,
) -> dict[str, Any]:
    """Extract function call graph and disassembly using Radare2."""
    file_name = session.input_file.name
    r2 = session.r2

    r2.cmd("aaa")  # Deep analysis — required for complete call graph
    raw_graph = r2.cmd("agCd")

    if not raw_graph:
        logger.error("%s: No functions found", file_name)
        return {}

    function_call_graph = ["digraph code {"]
    functions_info: dict[str, Any] = {}
    pattern = r'"(0x[0-9a-fA-F]+)" \[label="([^"]+)"\];'

    for line in raw_graph.split("\n"):
        stripped = line.strip()
        if not stripped:
            continue
        # Skip DOT header/footer lines by content (not hard-coded index)
        if any(stripped.startswith(prefix) for prefix in _DOT_SKIP_PREFIXES):
            continue

        # Clean up visual attributes
        cleaned = re.sub(r' URL="[^"]*"', "", stripped)
        cleaned = re.sub(r" \[.*color=[^\]]*\]", "", cleaned)
        function_call_graph.append(f"  {cleaned}")

        match = re.search(pattern, cleaned)
        if not match:
            continue

        address, name = match.groups()
        is_external = name.startswith("sym.imp.") or name.startswith("reloc.")
        functions_info[address] = {
            "function_name": name,
            "is_external": is_external,
            "instructions": [],
        }

        # Extract per-function disassembly
        func_data = r2.cmdj(f"pdfj @ {address}")
        if func_data and "ops" in func_data:
            for inst in func_data["ops"]:
                disasm = inst.get("disasm", "invalid")
                functions_info[address]["instructions"].append(disasm)
        else:
            # Import stub or unresolved function — leave instructions empty
            logger.debug(
                "%s: No disassembly for %s (%s) — likely import stub",
                file_name,
                address,
                name,
            )

    function_call_graph.append("}")
    dot_content = "\n".join(function_call_graph)

    return {"dot_content": dot_content, "functions": functions_info}
