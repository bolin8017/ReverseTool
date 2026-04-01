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

    def write_output(self, result: ExtractResult, output_dir: Path) -> list[Path]:
        written = []
        stem = result.input_file.stem

        if "dot_content" in result.data:
            dot_path = write_dot(result.data["dot_content"], output_dir / f"{stem}.dot")
            written.append(dot_path)

        if "functions" in result.data:
            json_path = write_functions_json(
                result.data["functions"], output_dir / f"{stem}.json"
            )
            written.append(json_path)

        return written
