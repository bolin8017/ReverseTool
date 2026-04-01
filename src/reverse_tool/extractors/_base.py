"""Abstract base class for feature extractors."""

from __future__ import annotations

import inspect
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Generic

from reverse_tool._typing import T_Session


@dataclass(frozen=True)
class ExtractResult:
    """Immutable extraction result."""

    extractor_name: str
    input_file: Path
    data: dict[str, Any]
    metadata: dict[str, Any] = field(default_factory=dict)


class BaseExtractor(ABC, Generic[T_Session]):
    """A feature extractor produces structured output from a backend session.

    Concrete subclasses are auto-registered via ``__init_subclass__``.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique extractor identifier (e.g. 'opcode', 'function_call')."""
        ...

    @property
    @abstractmethod
    def description(self) -> str:
        """Short human-readable description."""
        ...

    @property
    @abstractmethod
    def supported_backends(self) -> frozenset[str]:
        """Set of backend names this extractor supports."""
        ...

    @abstractmethod
    def extract(
        self,
        session: T_Session,
        input_file: Path,
        logger: logging.Logger,
    ) -> ExtractResult:
        """Extract features from a backend session."""
        ...

    @abstractmethod
    def write_output(self, result: ExtractResult, output_dir: Path) -> list[Path]:
        """Write results to disk. Returns paths of created files."""
        ...

    def supports_backend(self, backend: Any) -> bool:
        """Check if this extractor supports the given backend."""
        return backend.info.name in self.supported_backends

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        if inspect.isabstract(cls):
            return
        from reverse_tool.discovery import _register_extractor

        _register_extractor(cls)
