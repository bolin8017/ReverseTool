"""Ghidra-specific function call extraction logic.

Uses PyGhidra (Ghidra 12.0+) to run the extraction script.
"""

from __future__ import annotations

import json
import logging
import shutil
from pathlib import Path
from typing import Any

from reverse_tool.exceptions import BackendError
from reverse_tool.extractors._ghidra_runner import run_ghidra_script

_GHIDRA_SCRIPT_NAME = "ghidra_function_call.py"


def extract_function_calls_ghidra(
    session: Any,
    logger: logging.Logger,
) -> dict[str, Any]:
    """Extract function call graph and disassembly using Ghidra via PyGhidra."""
    scripts_dir = Path(__file__).parent / "_scripts"
    script_path = scripts_dir / _GHIDRA_SCRIPT_NAME
    file_name = session.input_file.name

    project_name = f"{file_name}_funcall_project"

    # The script writes output files into the project folder; pass the folder itself
    project_folder, _ = run_ghidra_script(
        session=session,
        script_path=script_path,
        project_name=project_name,
        output_name="",
        logger=logger,
    )

    try:
        dot_path = project_folder / f"{file_name}.dot"
        json_path = project_folder / f"{file_name}.json"

        if not dot_path.exists() or not json_path.exists():
            logger.error("%s: Output files not found", file_name)
            raise BackendError(f"Output files not found for {file_name}")

        dot_content = dot_path.read_text(encoding="utf-8")
        with open(json_path, encoding="utf-8") as f:
            functions = json.load(f)

        return {"dot_content": dot_content, "functions": functions}

    finally:
        shutil.rmtree(project_folder, ignore_errors=True)
