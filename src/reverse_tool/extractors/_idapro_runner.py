"""Shared IDA Pro subprocess runner."""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from reverse_tool.exceptions import BackendError, BackendTimeout

_TIMEOUT_EXIT_CODE = 124  # GNU coreutils `timeout` exit code


def _read_log_tail(log_path: Path, max_bytes: int = 500) -> str:
    """Read the tail of the IDA log file for error reporting.

    idat writes all output to its log file (-L), not to stdout/stderr.
    """
    if not log_path.exists():
        return "no log output"
    try:
        content = log_path.read_text(encoding="utf-8", errors="replace")
        return content[-max_bytes:].strip() if content else "empty log"
    except OSError:
        return "could not read log"


def run_ida_script(
    *,
    session: Any,
    script_path: Path,
    output_name: str,
    logger: logging.Logger,
) -> tuple[Path, Path]:
    """Run an IDAPython script via idat subprocess.

    ``output_name`` is a filename relative to the temp output folder that
    the script will write to. Pass an empty string when the script writes
    multiple files directly into the output folder.

    Returns ``(temp_dir, output_path)`` on success where
    ``output_path = temp_dir / output_name`` (or ``temp_dir`` when
    ``output_name`` is empty).
    Raises BackendTimeout on timeout, BackendError on non-zero exit.
    Caller is responsible for reading output files and cleaning up temp_dir.
    """
    file_name = session.input_file.name
    temp_dir = Path(tempfile.mkdtemp(prefix=f"ida_{file_name}_"))
    temp_db_path = temp_dir / f"{file_name}.i64"
    log_path = temp_dir / "ida.log"
    output_path = temp_dir / output_name if output_name else temp_dir

    env = {
        **os.environ,
        "_RT_OUTPUT": str(output_path),
        "_RT_BINARY": str(session.input_file),
        "QT_QPA_PLATFORM": "offscreen",
        "TVHEADLESS": "1",
    }

    cmd = [
        "timeout",
        "--kill-after=10",
        str(session.timeout),
        str(session.ida_path),
        "-A",
        "-c",
        f"-o{temp_db_path}",
        f"-L{log_path}",
        f"-S{script_path}",
        str(session.input_file),
    ]

    logger.debug("%s: Running IDA command: %s", file_name, " ".join(cmd))

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            env=env,
            timeout=session.timeout + 15,
        )
    except subprocess.TimeoutExpired as exc:
        logger.error(
            "%s: IDA Pro timed out (Python-level) after %ds",
            file_name,
            session.timeout,
        )
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise BackendTimeout(str(session.input_file), session.timeout) from exc

    if result.returncode == _TIMEOUT_EXIT_CODE:
        logger.error("%s: IDA Pro timed out after %ds", file_name, session.timeout)
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise BackendTimeout(str(session.input_file), session.timeout)

    # idat writes all diagnostic output to its log file, not stdout/stderr
    log_tail = _read_log_tail(log_path)

    # Strategy: missing output = hard failure; non-zero exit with output = warning only
    # (idat sometimes exits non-zero even on successful analysis)
    if output_name and not output_path.exists():
        logger.error(
            "%s: IDA Pro failed (exit %d, no output): %s",
            file_name,
            result.returncode,
            log_tail,
        )
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise BackendError(
            f"IDA Pro failed (exit {result.returncode}): output not created. {log_tail}"
        )

    if result.returncode != 0:
        # Non-zero but output exists — log warning and continue
        logger.warning(
            "%s: IDA Pro exited with code %d but output exists, continuing. Log: %s",
            file_name,
            result.returncode,
            log_tail,
        )

    return temp_dir, output_path
