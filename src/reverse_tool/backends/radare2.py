"""Radare2 reverse engineering backend."""

from __future__ import annotations

import contextlib
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from reverse_tool.backends._base import BackendInfo, BaseBackend
from reverse_tool.exceptions import BackendNotAvailable, BackendTimeout

_R2_TIMEOUT_SCRIPT = "_scripts/r2_timeout_check.sh"


@dataclass
class Radare2Session:
    """Active r2pipe session for binary analysis."""

    r2: Any  # r2pipe.open() instance
    input_file: Path


class Radare2Backend(BaseBackend["Radare2Session"]):
    """Radare2-based binary analysis backend.

    Session wraps an active r2pipe connection.
    """

    @property
    def info(self) -> BackendInfo:
        return BackendInfo(name="radare2", version="6.1.2")

    def validate_environment(self) -> None:
        if not shutil.which("r2"):
            raise BackendNotAvailable(
                "radare2",
                fix="Install Radare2: https://github.com/radareorg/radare2",
            )

    def _open_session(self, input_file: Path, timeout: int) -> Radare2Session:
        import r2pipe

        # Pre-flight timeout check
        if not self._check_timeout(input_file, timeout):
            raise BackendTimeout(str(input_file), timeout)

        r2 = r2pipe.open(str(input_file), flags=["-2"])
        return Radare2Session(r2=r2, input_file=input_file)

    def _close_session(self, session: Radare2Session) -> None:
        with contextlib.suppress(Exception):
            session.r2.quit()

    @staticmethod
    def _check_timeout(input_file: Path, timeout: int) -> bool:
        """Run pre-flight timeout check."""
        # Find script relative to extractors that use it
        script_candidates = list(
            Path(__file__).parent.parent.glob(
                "extractors/*/_scripts/r2_timeout_check.sh"
            )
        )
        if not script_candidates:
            return True  # Skip check if script not found

        script = script_candidates[0]
        if not os.access(script, os.X_OK):
            return True

        try:
            result = subprocess.run(
                [str(script), str(input_file), str(timeout)],
                capture_output=True,
                text=True,
                check=True,
            )
            return result.stdout.strip() == "true"
        except subprocess.CalledProcessError:
            return False
