"""Ghidra-specific opcode extraction logic.

Uses PyGhidra (Ghidra 12.0.4+) to run the extraction script.
"""

from __future__ import annotations

import csv
import logging
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

_GHIDRA_SCRIPT_NAME = "ghidra_opcode.py"
_TIMEOUT_EXIT_CODE = 124


def extract_opcodes_ghidra(
    session: Any,  # GhidraSession
    logger: logging.Logger,
) -> list[dict[str, Any]]:
    """Extract opcodes using Ghidra via PyGhidra.

    Creates a temp project, runs the opcode extraction script through
    pyghidra.run_script(), reads the resulting CSV, and cleans up.
    """
    scripts_dir = Path(__file__).parent / "_scripts"
    script_path = scripts_dir / _GHIDRA_SCRIPT_NAME
    file_name = session.input_file.name

    project_name = f"{file_name}_opcode_project"
    project_folder = Path(os.environ.get("TMPDIR", "/tmp")) / project_name
    temp_csv = project_folder / f"{file_name}.csv"

    project_folder.mkdir(parents=True, exist_ok=True)

    # Build a Python command that uses pyghidra.run_script()
    pyghidra_cmd = (
        "import pyghidra; "
        "pyghidra.run_script("
        f"binary_path={str(session.input_file)!r}, "
        f"script_path={str(script_path)!r}, "
        f"project_location={str(project_folder)!r}, "
        f"project_name={project_name!r}, "
        f"script_args=[{str(temp_csv)!r}], "
        "analyze=True"
        ")"
    )

    try:
        result = subprocess.run(
            [
                "timeout",
                "--kill-after=10",
                str(session.timeout),
                sys.executable,
                "-c",
                pyghidra_cmd,
            ],
            capture_output=True,
            text=True,
            env={
                **os.environ,
                "GHIDRA_INSTALL_DIR": str(os.environ.get("GHIDRA_INSTALL_DIR", "")),
            },
        )

        if result.returncode == _TIMEOUT_EXIT_CODE:
            logger.error(
                "%s: Ghidra analysis timed out after %ds",
                file_name,
                session.timeout,
            )
            return []

        if result.returncode != 0:
            stderr_tail = result.stderr[-500:] if result.stderr else "no output"
            logger.error(
                "%s: Ghidra failed (exit %d): %s",
                file_name,
                result.returncode,
                stderr_tail,
            )
            return []

        if not temp_csv.exists():
            logger.error(
                "%s: Output CSV not found after Ghidra analysis",
                file_name,
            )
            return []

        opcodes = []
        with open(temp_csv, encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                opcodes.append(
                    {
                        "addr": int(row["addr"]),
                        "opcode": row["opcode"],
                        "section_name": row["section_name"],
                    }
                )
        return opcodes

    except Exception as e:
        logger.exception("%s: Unexpected error: %s", file_name, e)
        return []
    finally:
        shutil.rmtree(project_folder, ignore_errors=True)
