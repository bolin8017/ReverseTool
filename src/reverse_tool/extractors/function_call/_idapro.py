"""IDA Pro-specific function call extraction logic."""

from __future__ import annotations

import json
import logging
import shutil
from pathlib import Path
from typing import Any

from reverse_tool.exceptions import BackendError
from reverse_tool.extractors._idapro_runner import run_ida_script

_IDA_SCRIPT_NAME = "idapro_function_call.py"


def extract_function_calls_idapro(
    session: Any,
    logger: logging.Logger,
) -> dict[str, Any]:
    """Extract function call graph and disassembly using IDA Pro."""
    scripts_dir = Path(__file__).parent / "_scripts"
    script_path = scripts_dir / _IDA_SCRIPT_NAME
    file_name = session.input_file.name

    # The script writes .dot and .json into the output folder
    temp_dir, _ = run_ida_script(
        session=session,
        script_path=script_path,
        output_name="",
        logger=logger,
    )

    try:
        dot_path = temp_dir / f"{file_name}.dot"
        json_path = temp_dir / f"{file_name}.json"

        if not dot_path.exists() or not json_path.exists():
            logger.error("%s: Output files not found", file_name)
            raise BackendError(f"Output files not found for {file_name}")

        dot_content = dot_path.read_text(encoding="utf-8")
        with open(json_path, encoding="utf-8") as f:
            functions = json.load(f)

        return {"dot_content": dot_content, "functions": functions}

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)
