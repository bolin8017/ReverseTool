"""Opcode feature extractor."""

from __future__ import annotations

import logging
from pathlib import Path

from reverse_tool.extractors._base import BaseExtractor, ExtractResult
from reverse_tool.extractors.opcode._writer import write_opcode_csv


class OpcodeExtractor(BaseExtractor):
    """Extract opcode mnemonics from binary files.

    Outputs CSV with columns: addr, opcode, section_name.
    """

    @property
    def name(self) -> str:
        return "opcode"

    @property
    def description(self) -> str:
        return "Extract opcode sequences from binaries"

    @property
    def supported_backends(self) -> frozenset[str]:
        return frozenset({"ghidra", "radare2"})

    def extract(
        self, session, input_file: Path, logger: logging.Logger
    ) -> ExtractResult:
        backend_name = type(session).__name__

        if "Ghidra" in backend_name:
            from reverse_tool.extractors.opcode._ghidra import (
                extract_opcodes_ghidra,
            )

            opcodes = extract_opcodes_ghidra(session, logger)
        elif "Radare2" in backend_name or "Null" in backend_name:
            if "Null" in backend_name:
                opcodes = [
                    {"addr": 0, "opcode": op, "section_name": ".text"}
                    for ops in session.opcodes.values()
                    for op in ops
                ]
            else:
                from reverse_tool.extractors.opcode._radare2 import (
                    extract_opcodes_radare2,
                )

                opcodes = extract_opcodes_radare2(session, logger)
        else:
            opcodes = []

        return ExtractResult(
            extractor_name=self.name,
            input_file=input_file,
            data={"opcodes": opcodes},
            metadata={"count": len(opcodes)},
        )

    def write_output(self, result: ExtractResult, output_dir: Path) -> list[Path]:
        csv_path = output_dir / f"{result.input_file.stem}.csv"
        write_opcode_csv(result.data["opcodes"], csv_path)
        return [csv_path]
