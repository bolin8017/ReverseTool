"""Function call feature extractor."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from reverse_tool.extractors._base import BaseExtractor, ExtractResult
from reverse_tool.extractors.function_call._writer import write_function_call_json


class FunctionCallExtractor(BaseExtractor):
    """Extract function call graphs and per-function disassembly.

    Outputs unified JSON with call graph + function details + metadata.
    """

    @property
    def name(self) -> str:
        return "function_call"

    @property
    def description(self) -> str:
        return "Extract function call graphs from binaries"

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
            from reverse_tool.extractors.function_call._ghidra import (
                extract_function_calls_ghidra,
            )

            features = extract_function_calls_ghidra(session, logger)
        elif isinstance(session, Radare2Session):
            from reverse_tool.extractors.function_call._radare2 import (
                extract_function_calls_radare2,
            )

            features = extract_function_calls_radare2(session, logger)
        elif isinstance(session, IdaproSession):
            from reverse_tool.extractors.function_call._idapro import (
                extract_function_calls_idapro,
            )

            features = extract_function_calls_idapro(session, logger)
        elif isinstance(session, NullSession):
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
            raise IncompatibleBackendError(
                "function_call",
                type(session).__name__,
                frozenset({"ghidra", "radare2", "idapro"}),
            )

        backend_name = type(session).__name__.replace("Session", "").lower()
        features["backend"] = backend_name

        return ExtractResult(
            extractor_name=self.name,
            input_file=input_file,
            data=features,
            metadata={"function_count": len(features.get("functions", {}))},
        )

    def write_output(self, result: ExtractResult, output_dir: Path) -> list[Path]:
        stem = result.input_file.stem
        functions = result.data.get("functions", {})
        dot_content = result.data.get("dot_content", "")
        backend = result.data.get("backend", "")

        json_path = write_function_call_json(
            functions,
            dot_content,
            output_dir / f"{stem}.json",
            input_file=result.input_file,
            backend=backend,
        )

        return [json_path]
