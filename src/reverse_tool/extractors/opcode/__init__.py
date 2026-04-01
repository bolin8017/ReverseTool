"""Opcode feature extractor."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from reverse_tool.extractors._base import BaseExtractor, ExtractResult
from reverse_tool.extractors.opcode._writer import write_opcode_jsonl


class OpcodeExtractor(BaseExtractor):
    """Extract opcode sequences from binary files.

    Outputs complete per-instruction data: mnemonic, full instruction,
    size, bytes, section. Primary format: JSONL with metadata.
    """

    @property
    def name(self) -> str:
        return "opcode"

    @property
    def description(self) -> str:
        return "Extract opcode sequences from binaries"

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

        sections: list[dict[str, Any]] = []
        binary_info: dict[str, Any] = {}

        if isinstance(session, GhidraSession):
            from reverse_tool.extractors.opcode._ghidra import (
                extract_opcodes_ghidra,
            )

            result_data = extract_opcodes_ghidra(session, logger)
            opcodes = result_data["opcodes"]
            sections = result_data.get("sections", [])
            binary_info = result_data.get("binary_info", {})
        elif isinstance(session, Radare2Session):
            from reverse_tool.extractors.opcode._radare2 import (
                extract_opcodes_radare2,
            )

            result_data = extract_opcodes_radare2(session, logger)
            opcodes = result_data["opcodes"]
            sections = result_data.get("sections", [])
            binary_info = result_data.get("binary_info", {})
        elif isinstance(session, IdaproSession):
            from reverse_tool.extractors.opcode._idapro import (
                extract_opcodes_idapro,
            )

            result_data = extract_opcodes_idapro(session, logger)
            opcodes = result_data["opcodes"]
            sections = result_data.get("sections", [])
            binary_info = result_data.get("binary_info", {})
        elif isinstance(session, NullSession):
            opcodes = [
                {
                    "index": i,
                    "addr": 0,
                    "mnemonic": op,
                    "instruction": op,
                    "size": 1,
                    "bytes": "",
                    "section": ".text",
                }
                for i, op in enumerate(
                    op for ops in session.opcodes.values() for op in ops
                )
            ]
        else:
            raise IncompatibleBackendError(
                "opcode",
                type(session).__name__,
                frozenset({"ghidra", "radare2", "idapro"}),
            )

        backend_name = type(session).__name__.replace("Session", "").lower()

        return ExtractResult(
            extractor_name=self.name,
            input_file=input_file,
            data={
                "opcodes": opcodes,
                "backend": backend_name,
                "sections": sections,
                "binary_info": binary_info,
            },
            metadata={"count": len(opcodes)},
        )

    def write_output(self, result: ExtractResult, output_dir: Path) -> list[Path]:
        stem = result.input_file.stem

        jsonl_path = write_opcode_jsonl(
            result.data["opcodes"],
            output_dir / f"{stem}.jsonl",
            input_file=result.input_file,
            backend=result.data.get("backend", ""),
            sections=result.data.get("sections", []),
            binary_info=result.data.get("binary_info", {}),
        )
        return [jsonl_path]
