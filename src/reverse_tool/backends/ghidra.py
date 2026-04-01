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
        self._detected_version: str | None = None

    @property
    def ghidra_path(self) -> Path | None:
        return self._ghidra_path

    @property
    def info(self) -> BackendInfo:
        version = self._detected_version or f"{self.REQUIRED_VERSION}+"
        return BackendInfo(name="ghidra", version=version)

    REQUIRED_VERSION = "12.0"

    def validate_environment(self) -> None:
        if self._ghidra_path is None:
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

        self._check_version()

    def _check_version(self) -> None:
        """Check Ghidra version via application.properties."""
        from reverse_tool.exceptions import BackendVersionError

        # analyzeHeadless is at <ghidra_root>/support/analyzeHeadless
        # application.properties is at <ghidra_root>/Ghidra/application.properties
        if self._ghidra_path is None:
            return  # Cannot check version without path
        ghidra_root = self._ghidra_path.resolve().parent.parent
        props_file = ghidra_root / "Ghidra" / "application.properties"

        if not props_file.exists():
            return  # Can't determine version, proceed

        version = None
        with open(props_file, encoding="utf-8") as f:
            for line in f:
                if line.startswith("application.version="):
                    version = line.strip().split("=", 1)[1]
                    break

        if version is None:
            return

        self._detected_version = version

        major_minor = ".".join(version.split(".")[:2])
        found = tuple(int(x) for x in major_minor.split("."))
        required = tuple(int(x) for x in self.REQUIRED_VERSION.split("."))
        if found < required:
            raise BackendVersionError(
                "ghidra",
                found=version,
                expected=f"{self.REQUIRED_VERSION}+",
            )

    def _open_session(self, input_file: Path, timeout: int) -> GhidraSession:
        if self._ghidra_path is None:
            raise BackendNotAvailable(
                "ghidra", fix="Call validate_environment() or provide --ghidra-path"
            )
        return GhidraSession(
            ghidra_path=self._ghidra_path,
            input_file=input_file,
            timeout=timeout,
        )

    def _close_session(self, session: GhidraSession) -> None:
        pass  # No resources to release — each extractor manages its own temp files
