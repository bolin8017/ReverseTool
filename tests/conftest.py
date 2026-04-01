"""Shared test fixtures for ReverseTool."""

import pytest

from reverse_tool.backends.null import NullBackend, NullBackendConfig

MINIMAL_DATA = NullBackendConfig(
    functions={
        "main": {"addr": 0x401000, "size": 42, "calls": ["printf", "exit"]},
        "printf": {"addr": 0x401100, "size": 10, "calls": []},
        "exit": {"addr": 0x401200, "size": 8, "calls": []},
    },
    opcodes={
        "main": ["push", "mov", "sub", "call", "call", "add", "ret"],
        "printf": ["push", "mov", "ret"],
        "exit": ["mov", "syscall"],
    },
    metadata={"arch": "x86_64", "format": "ELF"},
)

EMPTY_DATA = NullBackendConfig()


@pytest.fixture
def null_backend() -> NullBackend:
    return NullBackend(MINIMAL_DATA)


@pytest.fixture
def empty_null_backend() -> NullBackend:
    return NullBackend(EMPTY_DATA)


@pytest.fixture
def failing_backend() -> NullBackend:
    return NullBackend(
        NullBackendConfig(
            raise_on_open=RuntimeError("Backend crashed"),
        )
    )
