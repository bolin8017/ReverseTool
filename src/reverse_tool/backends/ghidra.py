"""Ghidra reverse engineering backend."""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path

from reverse_tool.backends._base import BackendInfo, BaseBackend
from reverse_tool.exceptions import BackendNotAvailable


@dataclass(frozen=True)
class GhidraSession:
    """Lightweight session containing validated paths for Ghidra analysis."""

    ghidra_path: Path
    input_file: Path
    timeout: int


class GhidraBackend(BaseBackend["GhidraSession"]):
    """Ghidra-based binary analysis backend.

    Session is a lightweight path container. Each extractor runs its own
    analyzeHeadless subprocess with a specific postScript.
    """

    def __init__(self, ghidra_path: str | Path | None = None) -> None:
        self._ghidra_path = Path(ghidra_path) if ghidra_path else None

    @property
    def info(self) -> BackendInfo:
        return BackendInfo(name="ghidra", version="12.0.4")

    def validate_environment(self) -> None:
        if self._ghidra_path is None:
            # Try to find analyzeHeadless on PATH
            found = shutil.which("analyzeHeadless")
            if found:
                self._ghidra_path = Path(found)
            else:
                raise BackendNotAvailable(
                    "ghidra",
                    fix="Provide --ghidra-path or add analyzeHeadless to PATH",
                )
        if not self._ghidra_path.exists():
            raise BackendNotAvailable(
                "ghidra",
                fix=f"analyzeHeadless not found at {self._ghidra_path}",
            )

    def _open_session(self, input_file: Path, timeout: int) -> GhidraSession:
        assert self._ghidra_path is not None, (  # noqa: S101
            "validate_environment() must be called first"
        )
        return GhidraSession(
            ghidra_path=self._ghidra_path,
            input_file=input_file,
            timeout=timeout,
        )

    def _close_session(self, session: GhidraSession) -> None:
        pass  # No resources to release — each extractor manages its own temp files
