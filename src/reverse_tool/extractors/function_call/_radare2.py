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
                    file_name,
                    address,
                    e,
                )
                functions_info[address]["instructions"].append("error")

        function_call_graph.append("}")
        dot_content = "\n".join(function_call_graph)

        return {"dot_content": dot_content, "functions": functions_info}

    except Exception as e:
        logger.exception("%s: Unexpected error: %s", file_name, e)
        return {}
