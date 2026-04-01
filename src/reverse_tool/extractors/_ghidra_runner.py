"""Shared Ghidra/PyGhidra subprocess runner."""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from reverse_tool.exceptions import BackendError, BackendTimeout

_LAUNCHER = """\
import os
import pyghidra

pyghidra.run_script(
    binary_path=os.environ["_RT_BINARY"],
    script_path=os.environ["_RT_SCRIPT"],
    project_location=os.environ["_RT_PROJECT"],
    project_name=os.environ["_RT_PROJECT_NAME"],
    script_args=[os.environ["_RT_OUTPUT"]],
    analyze=True,
)
"""

_TIMEOUT_EXIT_CODE = 124  # GNU coreutils `timeout` exit code for timed-out commands


def run_ghidra_script(
    *,
    session: Any,
    script_path: Path,
    project_name: str,
    output_name: str,
    logger: logging.Logger,
) -> tuple[Path, Path]:
    """Run a Ghidra script via PyGhidra subprocess.

    ``output_name`` is a filename (or empty string) relative to the temp project
    folder that the script will write to.  Pass an empty string when the script
    writes directly into the project folder (e.g. function-call extractor).

    Returns ``(project_folder, output_path)`` on success where
    ``output_path = project_folder / output_name`` (or ``project_folder`` when
    ``output_name`` is empty).
    Raises BackendTimeout on timeout, BackendError on non-zero exit.
    Caller is responsible for reading output files and cleaning up.
    """
    file_name = session.input_file.name
    project_folder = Path(
        tempfile.mkdtemp(prefix=f"{file_name}_", suffix=f"_{project_name}")
    )
    output_path = project_folder / output_name if output_name else project_folder

    env = {
        **os.environ,
        "_RT_BINARY": str(session.input_file),
        "_RT_SCRIPT": str(script_path),
        "_RT_PROJECT": str(project_folder),
        "_RT_PROJECT_NAME": project_name,
        "_RT_OUTPUT": str(output_path),
    }

    try:
        result = subprocess.run(
            [
                "timeout",
                "--kill-after=10",
                str(session.timeout),
                sys.executable,
                "-c",
                _LAUNCHER,
            ],
            capture_output=True,
            text=True,
            env=env,
            timeout=session.timeout + 15,
        )
    except subprocess.TimeoutExpired as exc:
        logger.error(
            "%s: Ghidra timed out (Python-level) after %ds",
            file_name,
            session.timeout,
        )
        shutil.rmtree(project_folder, ignore_errors=True)
        raise BackendTimeout(str(session.input_file), session.timeout) from exc

    if result.returncode == _TIMEOUT_EXIT_CODE:
        logger.error("%s: Ghidra timed out after %ds", file_name, session.timeout)
        shutil.rmtree(project_folder, ignore_errors=True)
        raise BackendTimeout(str(session.input_file), session.timeout)

    if result.returncode != 0:
        stderr_tail = result.stderr[-500:] if result.stderr else "no output"
        logger.error(
            "%s: Ghidra failed (exit %d): %s", file_name, result.returncode, stderr_tail
        )
        shutil.rmtree(project_folder, ignore_errors=True)
        raise BackendError(f"Ghidra failed (exit {result.returncode}): {stderr_tail}")

    # Verify output was actually created
    if output_name and not output_path.exists():
        stderr_tail = result.stderr[-500:] if result.stderr else "no output"
        logger.error(
            "%s: Ghidra succeeded (exit 0) but output not created: %s",
            file_name,
            stderr_tail,
        )
        shutil.rmtree(project_folder, ignore_errors=True)
        raise BackendError(f"Ghidra completed but output not created. {stderr_tail}")

    return project_folder, output_path
