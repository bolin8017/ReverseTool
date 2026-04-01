"""IDA Pro reverse engineering backend."""

from __future__ import annotations

import re
import shutil
from dataclasses import dataclass
from pathlib import Path

from reverse_tool.backends._base import BackendInfo, BaseBackend
from reverse_tool.exceptions import BackendNotAvailable


@dataclass(frozen=True)
class IdaproSession:
    """Lightweight session containing validated paths for IDA Pro analysis."""

    ida_path: Path
    input_file: Path
    timeout: int


class IdaproBackend(BaseBackend["IdaproSession"]):
    """IDA Pro-based binary analysis backend (local-only, no Docker).

    Session is a lightweight path container. Each extractor runs its own
    idat subprocess with a specific IDAPython script.
    """

    REQUIRED_VERSION = "9.3"

    def __init__(self, ida_path: str | Path | None = None) -> None:
        self._ida_path = Path(ida_path) if ida_path else None
        self._detected_version: str | None = None

    @property
    def ida_path(self) -> Path | None:
        return self._ida_path

    @property
    def info(self) -> BackendInfo:
        version = self._detected_version or f"{self.REQUIRED_VERSION}+"
        return BackendInfo(name="idapro", version=version)

    def validate_environment(self) -> None:
        if self._ida_path is None:
            found = shutil.which("idat")
            if found:
                self._ida_path = Path(found)
            else:
                raise BackendNotAvailable(
                    "idapro",
                    fix="Provide --ida-path or add idat to PATH",
                )
        if not self._ida_path.exists():
            raise BackendNotAvailable(
                "idapro",
                fix=f"idat not found at {self._ida_path}",
            )

        self._check_version()

    def _check_version(self) -> None:
        """Check IDA Pro version via python/ida_pro.py SDK version string."""
        from reverse_tool.exceptions import BackendVersionError

        # idat is at <ida_root>/idat; version is in <ida_root>/python/ida_pro.py
        if self._ida_path is None:
            return  # Cannot check version without path
        ida_root = self._ida_path.resolve().parent
        ida_pro_py = ida_root / "python" / "ida_pro.py"

        if not ida_pro_py.exists():
            return  # Can't determine version, proceed

        version = None
        # Look for docstring pattern: """IDA SDK v9.3."""
        pattern = re.compile(r"IDA SDK v(\d+\.\d+)")
        with open(ida_pro_py, encoding="utf-8", errors="ignore") as f:
            for line in f:
                match = pattern.search(line)
                if match:
                    version = match.group(1)
                    break

        if version is None:
            return  # Can't determine version, proceed

        self._detected_version = version

        found = tuple(int(x) for x in version.split("."))
        required = tuple(int(x) for x in self.REQUIRED_VERSION.split("."))
        if found < required:
            raise BackendVersionError(
                "idapro",
                found=version,
                expected=f"{self.REQUIRED_VERSION}+",
            )

    def _open_session(self, input_file: Path, timeout: int) -> IdaproSession:
        if self._ida_path is None:
            raise BackendNotAvailable(
                "idapro", fix="Call validate_environment() or provide --ida-path"
            )
        return IdaproSession(
            ida_path=self._ida_path,
            input_file=input_file,
            timeout=timeout,
        )

    def _close_session(self, session: IdaproSession) -> None:
        pass  # No resources to release — each extractor manages its own temp files
