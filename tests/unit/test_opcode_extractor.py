import logging
from pathlib import Path

import pytest

from reverse_tool.backends.null import NullBackend, NullBackendConfig
from reverse_tool.extractors.opcode import OpcodeExtractor

pytestmark = pytest.mark.unit


@pytest.fixture
def opcode_extractor():
    return OpcodeExtractor()


class TestOpcodeExtractor:
    def test_name_and_description(self, opcode_extractor):
        assert opcode_extractor.name == "opcode"
        assert "opcode" in opcode_extractor.description.lower()

    def test_supported_backends(self, opcode_extractor):
        assert "ghidra" in opcode_extractor.supported_backends
        assert "radare2" in opcode_extractor.supported_backends

    def test_extract_with_null_backend(self, opcode_extractor, tmp_path):
        config = NullBackendConfig(
            opcodes={"main": ["push", "mov", "ret"], "exit": ["mov", "syscall"]},
        )
        backend = NullBackend(config)
        binary = tmp_path / "test_bin"
        binary.write_bytes(b"\x00")
        log = logging.getLogger("test")

        with backend.session(binary) as session:
            result = opcode_extractor.extract(session, binary, log)

        assert result.extractor_name == "opcode"
        assert len(result.data["opcodes"]) == 5  # 3 + 2
        assert result.data["opcodes"][0]["opcode"] == "push"

    def test_write_output_creates_csv(self, opcode_extractor, tmp_path):
        from reverse_tool.extractors._base import ExtractResult

        result = ExtractResult(
            extractor_name="opcode",
            input_file=Path("test_bin"),
            data={
                "opcodes": [
                    {"addr": 1, "opcode": "push", "section_name": ".text"},
                    {"addr": 2, "opcode": "ret", "section_name": ".text"},
                ]
            },
        )
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        written = opcode_extractor.write_output(result, output_dir)
        assert len(written) == 1
        assert written[0].suffix == ".csv"
        assert written[0].exists()

    def test_auto_registered(self):
        from reverse_tool.discovery import discover_extractors

        registry = discover_extractors()
        assert "opcode" in registry
