"""IDA Pro-specific opcode extraction logic."""

from __future__ import annotations

import csv
import logging
import shutil
from pathlib import Path
from typing import Any

from reverse_tool.extractors._idapro_runner import run_ida_script

_IDA_SCRIPT_NAME = "idapro_opcode.py"


def extract_opcodes_idapro(
    session: Any,
    logger: logging.Logger,
) -> dict[str, Any]:
    """Extract opcodes using IDA Pro via idat subprocess."""
    scripts_dir = Path(__file__).parent / "_scripts"
    script_path = scripts_dir / _IDA_SCRIPT_NAME
    file_name = session.input_file.name

    temp_dir, temp_csv = run_ida_script(
        session=session,
        script_path=script_path,
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
        shutil.rmtree(temp_dir, ignore_errors=True)
