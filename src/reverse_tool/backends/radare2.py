"""Radare2 reverse engineering backend."""

from __future__ import annotations

import contextlib
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from reverse_tool.backends._base import BackendInfo, BaseBackend
from reverse_tool.exceptions import BackendNotAvailable


@dataclass
class Radare2Session:
    """Active r2pipe session for binary analysis."""

    r2: Any  # r2pipe.open() instance
    input_file: Path


class Radare2Backend(BaseBackend["Radare2Session"]):
    """Radare2-based binary analysis backend.

    Session wraps an active r2pipe connection.
    """

    def __init__(self) -> None:
        self._detected_version: str | None = None

    @property
    def info(self) -> BackendInfo:
        version = self._detected_version or f"{self.REQUIRED_VERSION}+"
        return BackendInfo(name="radare2", version=version)

    REQUIRED_VERSION = "6.1"

    def validate_environment(self) -> None:
        r2_path = shutil.which("r2")
        if not r2_path:
            raise BackendNotAvailable(
                "radare2",
                fix="Install Radare2 6.1+: https://github.com/radareorg/radare2",
            )

        import subprocess

        try:
            result = subprocess.run(
                [r2_path, "-v"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            version_line = result.stdout.strip().split("\n")[0]
            # e.g. "radare2 6.1.2 ..."
            parts = version_line.split()
            if len(parts) >= 2:
                version = parts[1]
                self._detected_version = version
                major_minor = ".".join(version.split(".")[:2])
                found = tuple(int(x) for x in major_minor.split("."))
                required = tuple(int(x) for x in self.REQUIRED_VERSION.split("."))
                if found < required:
                    from reverse_tool.exceptions import BackendVersionError

                    raise BackendVersionError(
                        "radare2",
                        found=version,
                        expected=f"{self.REQUIRED_VERSION}+",
                    )
        except (subprocess.TimeoutExpired, IndexError, OSError):
            pass  # If version check fails, proceed anyway

    def _open_session(self, input_file: Path, timeout: int) -> Radare2Session:
        import r2pipe

        r2 = r2pipe.open(str(input_file), flags=["-2"])
        r2.cmd(f"e anal.timeout={timeout}")
        return Radare2Session(r2=r2, input_file=input_file)

    def _close_session(self, session: Radare2Session) -> None:
        with contextlib.suppress(Exception):
            session.r2.quit()
