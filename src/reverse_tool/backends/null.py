"""Programmable null backend for testing."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from reverse_tool.backends._base import BackendInfo, BaseBackend


@dataclass
class NullSession:
    """Session returned by NullBackend. Holds predetermined data."""

    binary_path: Path
    functions: dict[str, Any] = field(default_factory=dict)
    opcodes: dict[str, list[str]] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class NullBackendConfig:
    """Configuration for NullBackend behavior."""

    functions: dict[str, Any] = field(default_factory=dict)
    opcodes: dict[str, list[str]] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
    raise_on_open: Exception | None = None


class NullBackend(BaseBackend[NullSession]):
    """A programmable backend that returns predetermined data.

    Designed for unit testing — zero external dependencies.
    """

    def __init__(self, config: NullBackendConfig | None = None) -> None:
        self._config = config or NullBackendConfig()

    @property
    def info(self) -> BackendInfo:
        return BackendInfo(name="null", version="0.0.0")

    def validate_environment(self) -> None:
        pass

    def _open_session(self, input_file: Path, timeout: int) -> NullSession:
        if self._config.raise_on_open is not None:
            raise self._config.raise_on_open
        return NullSession(
            binary_path=input_file,
            functions=dict(self._config.functions),
            opcodes=dict(self._config.opcodes),
            metadata=dict(self._config.metadata),
        )

    def _close_session(self, session: NullSession) -> None:
        pass
