"""Structured exception hierarchy for ReverseTool."""

from __future__ import annotations


class ReverseToolError(Exception):
    """Base for all framework errors."""


class BackendError(ReverseToolError):
    """Backend-related failures."""


class BackendNotAvailable(BackendError):
    """Backend tool not found or not configured."""

    def __init__(self, backend: str, *, fix: str = "") -> None:
        self.backend = backend
        self.fix = fix
        msg = f"Backend not available: {backend}"
        if fix:
            msg += f". Fix: {fix}"
        super().__init__(msg)


class BackendVersionError(BackendError):
    """Backend version is unsupported."""

    def __init__(self, backend: str, found: str, expected: str) -> None:
        self.backend = backend
        self.found = found
        self.expected = expected
        super().__init__(f"{backend}: found version {found}, expected {expected}")


class BackendTimeout(BackendError):
    """Analysis exceeded timeout."""

    def __init__(self, input_file: str, timeout: int) -> None:
        self.input_file = input_file
        self.timeout = timeout
        super().__init__(f"Timeout ({timeout}s) exceeded for {input_file}")


class ExtractionError(ReverseToolError):
    """Extraction-phase failures."""


class IncompatibleBackendError(ExtractionError):
    """Extractor does not support the selected backend."""

    def __init__(self, extractor: str, backend: str, supported: frozenset[str]) -> None:
        self.extractor = extractor
        self.backend = backend
        self.supported = supported
        super().__init__(
            f"Extractor {extractor!r} does not support backend {backend!r}. "
            f"Supported: {', '.join(sorted(supported))}"
        )


class OutputWriteError(ReverseToolError):
    """Failed to write extraction results."""


class ConfigError(ReverseToolError):
    """Configuration file or value error."""
