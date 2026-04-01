import json

import pytest

from reverse_tool.extractors.function_call._writer import write_function_call_json

pytestmark = pytest.mark.unit


class TestFunctionCallJSONWriter:
    def test_writes_json_with_metadata(self, tmp_path):
        binary = tmp_path / "test.bin"
        binary.write_bytes(b"\x00\x01\x02\x03")

        functions = {
            "0x1000": {
                "function_name": "main",
                "is_external": False,
                "instructions": ["nop", "ret"],
            }
        }
        dot_content = 'digraph code {\n  "0x1000";\n}'
        out = write_function_call_json(
            functions,
            dot_content,
            tmp_path / "graph.json",
            input_file=binary,
            backend="ghidra",
        )
        assert out.exists()
        data = json.loads(out.read_text())
        assert data["meta"]["extractor"] == "function_call"
        assert data["meta"]["function_count"] == 1
        assert "sha256" in data["meta"]
        assert data["dot"] == dot_content
        assert len(data["call_graph"]["nodes"]) == 1

    def test_writes_json_without_input_file(self, tmp_path):
        out = write_function_call_json(
            {}, "", tmp_path / "empty.json", backend="radare2"
        )
        data = json.loads(out.read_text())
        assert data["meta"]["function_count"] == 0
        assert "sha256" not in data["meta"]
