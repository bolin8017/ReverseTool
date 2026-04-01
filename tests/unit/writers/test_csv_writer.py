import json

import pytest

from reverse_tool.extractors.opcode._writer import write_opcode_jsonl

pytestmark = pytest.mark.unit


class TestJSONLWriter:
    def test_writes_valid_jsonl_with_metadata(self, tmp_path):
        binary = tmp_path / "test.bin"
        binary.write_bytes(b"\x00\x01\x02\x03")

        opcodes = [
            {
                "index": 0,
                "addr": 1,
                "mnemonic": "nop",
                "instruction": "nop",
                "size": 1,
                "bytes": "90",
                "section": ".text",
                "type": "nop",
            },
        ]
        out = write_opcode_jsonl(
            opcodes,
            tmp_path / "out.jsonl",
            input_file=binary,
            backend="radare2",
            sections=[
                {
                    "name": ".text",
                    "size": 100,
                    "vaddr": 0,
                    "paddr": 0,
                    "perm": "-r-x",
                    "type": "PROGBITS",
                }
            ],
            binary_info={
                "arch": "x86",
                "bits": 32,
                "format": "elf",
                "os": "linux",
                "endian": "little",
            },
        )
        assert out.exists()
        data = json.loads(out.read_text())
        assert "sha256" in data["meta"]
        assert "md5" in data["meta"]
        assert data["meta"]["file_size"] == 4
        assert data["meta"]["binary_info"]["arch"] == "x86"
        assert len(data["sections"]) == 1
        assert len(data["opcodes"]) == 1

    def test_jsonl_without_input_file(self, tmp_path):
        out = write_opcode_jsonl([], tmp_path / "empty.jsonl")
        data = json.loads(out.read_text())
        assert data["meta"]["instruction_count"] == 0
        assert "sha256" not in data["meta"]
