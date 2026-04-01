import pytest

from reverse_tool.exceptions import (
    BackendError,
    BackendNotAvailable,
    BackendTimeout,
    BackendVersionError,
    ConfigError,
    ExtractionError,
    IncompatibleBackendError,
    OutputWriteError,
    ReverseToolError,
)

pytestmark = pytest.mark.unit


class TestExceptionHierarchy:
    def test_all_inherit_from_reverse_tool_error(self):
        exceptions = [
            BackendError,
            BackendNotAvailable,
            BackendVersionError,
            BackendTimeout,
            ExtractionError,
            IncompatibleBackendError,
            OutputWriteError,
            ConfigError,
        ]
        for exc_cls in exceptions:
            assert issubclass(exc_cls, ReverseToolError)

    def test_backend_exceptions_inherit_from_backend_error(self):
        for exc_cls in [BackendNotAvailable, BackendVersionError, BackendTimeout]:
            assert issubclass(exc_cls, BackendError)

    def test_extraction_exceptions_inherit_from_extraction_error(self):
        assert issubclass(IncompatibleBackendError, ExtractionError)

    def test_exceptions_are_catchable_with_base(self):
        with pytest.raises(ReverseToolError):
            raise BackendNotAvailable("ghidra", fix="Install Ghidra 12.0.4")

    def test_backend_not_available_message(self):
        exc = BackendNotAvailable("ghidra", fix="Install Ghidra 12.0.4")
        assert "ghidra" in str(exc)
        assert exc.fix == "Install Ghidra 12.0.4"

    def test_backend_not_available_no_fix(self):
        exc = BackendNotAvailable("radare2")
        assert "radare2" in str(exc)
        assert exc.fix == ""

    def test_backend_version_error_message(self):
        exc = BackendVersionError("ghidra", found="11.0", expected="12.0.4")
        assert exc.backend == "ghidra"
        assert exc.found == "11.0"
        assert exc.expected == "12.0.4"
        assert "11.0" in str(exc)
        assert "12.0.4" in str(exc)

    def test_backend_timeout_message(self):
        exc = BackendTimeout("malware.exe", timeout=300)
        assert exc.input_file == "malware.exe"
        assert exc.timeout == 300
        assert "300" in str(exc)
        assert "malware.exe" in str(exc)

    def test_incompatible_backend_error_message(self):
        exc = IncompatibleBackendError(
            "opcode", "null", frozenset({"ghidra", "radare2"})
        )
        assert exc.extractor == "opcode"
        assert exc.backend == "null"
        assert "ghidra" in str(exc) or "radare2" in str(exc)
