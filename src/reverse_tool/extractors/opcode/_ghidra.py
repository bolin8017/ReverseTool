"""Ghidra-specific opcode extraction logic.

Uses PyGhidra (Ghidra 12.0+) to run the extraction script.
"""

from __future__ import annotations

import csv
import logging
import shutil
from pathlib import Path
from typing import Any

from reverse_tool.extractors._ghidra_runner import run_ghidra_script

_GHIDRA_SCRIPT_NAME = "ghidra_opcode.py"


def extract_opcodes_ghidra(
    session: Any,
    logger: logging.Logger,
) -> dict[str, Any]:
    """Extract opcodes using Ghidra via PyGhidra."""
    scripts_dir = Path(__file__).parent / "_scripts"
    script_path = scripts_dir / _GHIDRA_SCRIPT_NAME
    file_name = session.input_file.name

    project_name = f"{file_name}_opcode_project"
    project_folder, temp_csv = run_ghidra_script(
        session=session,
        script_path=script_path,
        project_name=project_name,
        output_name=f"{file_name}.csv",
        logger=logger,
    )

    try:
        if not temp_csv.exists():
            logger.error("%s: Output CSV not found", file_name)
            return {"opcodes": [], "sections": [], "binary_info": {}}

        opcodes: list[dict[str, Any]] = []
        binary_info: dict[str, Any] = {}

        with open(temp_csv, encoding="utf-8") as f:
            reader = csv.reader(f)
            for row in reader:
                if not row:
                    continue
                # Metadata row
                if row[0] == "#meta":
                    binary_info = {
                        "arch": row[1] if len(row) > 1 else "",
                        "bits": int(row[2]) if len(row) > 2 else 0,
                        "endian": row[3] if len(row) > 3 else "",
                    }
                    continue
                # Header row
                if row[0] == "index":
                    continue
                # Data row
                try:
                    opcodes.append(
                        {
                            "index": int(row[0]),
                            "addr": int(row[1], 0),  # support 0x prefix
                            "mnemonic": row[2],
                            "instruction": row[3],
                            "size": int(row[4]),
                            "bytes": row[5],
                            "section": row[6],
                        }
                    )
                except (IndexError, ValueError) as e:
                    logger.warning("Skipping malformed CSV row: %s", e)
                    continue

        return {
            "opcodes": opcodes,
            "sections": [],
            "binary_info": binary_info,
        }

    finally:
        shutil.rmtree(project_folder, ignore_errors=True)
