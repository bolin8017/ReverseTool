"""Abstract base class for reverse engineering backends."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Generic

from reverse_tool._typing import T_Session


@dataclass(frozen=True)
class BackendInfo:
    """Immutable backend metadata."""

    name: str
    version: str


class BaseBackend(ABC, Generic[T_Session]):
    """A backend provides a reverse engineering tool (Ghidra, Radare2, etc.).

    Subclasses implement ``_open_session`` and ``_close_session``.
    Callers use the ``session`` context manager — never call open/close directly.
    """

    @property
    @abstractmethod
    def info(self) -> BackendInfo:
        """Backend name and version."""
        ...

    @abstractmethod
    def validate_environment(self) -> None:
        """Check that the backend tool is installed and usable.

        Raises:
            BackendNotAvailable: If prerequisites are missing.
        """
        ...

    @abstractmethod
    def _open_session(self, input_file: Path, timeout: int) -> T_Session:
        """Open an analysis session. Called by ``session()``."""
        ...

    @abstractmethod
    def _close_session(self, session: T_Session) -> None:
        """Close an analysis session. Called by ``session()``."""
        ...

    @contextmanager
    def session(self, input_file: Path, timeout: int = 600) -> Iterator[T_Session]:
        """Context manager for backend session lifecycle.

        This is the ONLY public API for session management.
        """
        s = self._open_session(input_file, timeout)
        try:
            yield s
        finally:
            self._close_session(s)
