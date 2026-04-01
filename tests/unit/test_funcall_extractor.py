import logging
from pathlib import Path

import pytest

from reverse_tool.backends.null import NullBackend, NullBackendConfig
from reverse_tool.extractors.function_call import FunctionCallExtractor

pytestmark = pytest.mark.unit


@pytest.fixture
def funcall_extractor():
    return FunctionCallExtractor()


class TestFunctionCallExtractor:
    def test_name_and_description(self, funcall_extractor):
        assert funcall_extractor.name == "function_call"
        assert "function" in funcall_extractor.description.lower()

    def test_supported_backends(self, funcall_extractor):
        assert "ghidra" in funcall_extractor.supported_backends
        assert "radare2" in funcall_extractor.supported_backends

    def test_supported_backends_includes_idapro(self, funcall_extractor):
        assert "idapro" in funcall_extractor.supported_backends

    def test_extract_with_null_backend(self, funcall_extractor, tmp_path):
        config = NullBackendConfig(
            functions={
                "main": {"addr": 0x1000, "size": 42, "calls": ["printf"]},
                "printf": {"addr": 0x2000, "size": 10, "calls": []},
            },
        )
        backend = NullBackend(config)
        binary = tmp_path / "test_bin"
        binary.write_bytes(b"\x00")
        log = logging.getLogger("test")

        with backend.session(binary) as session:
            result = funcall_extractor.extract(session, binary, log)

        assert result.extractor_name == "function_call"
        assert "digraph" in result.data["dot_content"]
        assert "main" in result.data["functions"]

    def test_write_output_creates_json_and_dot(self, funcall_extractor, tmp_path):
        from reverse_tool.extractors._base import ExtractResult

        result = ExtractResult(
            extractor_name="function_call",
            input_file=Path("test_bin"),
            data={
                "dot_content": "digraph code {}",
                "functions": {"0x1000": {"function_name": "main"}},
                "backend": "null",
            },
        )
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        written = funcall_extractor.write_output(result, output_dir)
        assert len(written) == 1
        assert written[0].suffix == ".json"
        assert written[0].exists()

    def test_auto_registered(self):
        from reverse_tool.discovery import discover_extractors

        registry = discover_extractors()
        assert "function_call" in registry
