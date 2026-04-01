import json

import pytest

from reverse_tool.extractors.function_call._writer import write_function_call_json

pytestmark = pytest.mark.unit


class TestJSONWriter:
    def test_writes_valid_json_with_metadata(self, tmp_path):
        functions = {
            "0x1000": {"function_name": "main", "instructions": ["push rbp", "ret"]},
        }
        out = write_function_call_json(functions, "digraph {}", tmp_path / "funcs.json")
        assert out.exists()
        parsed = json.loads(out.read_text())
        assert "meta" in parsed
        assert parsed["meta"]["function_count"] == 1
        assert "call_graph" in parsed
        assert len(parsed["call_graph"]["nodes"]) == 1

    def test_round_trip(self, tmp_path):
        functions = {"0x1": {"function_name": "a", "instructions": ["nop"]}}
        out = write_function_call_json(functions, "digraph {}", tmp_path / "rt.json")
        parsed = json.loads(out.read_text())
        assert parsed["call_graph"]["functions"] == functions


class TestJSONWriterWithMetadata:
    def test_writes_json_with_file_hash(self, tmp_path):
        binary = tmp_path / "test.bin"
        binary.write_bytes(b"\xde\xad")

        functions = {"0x1000": {"function_name": "main", "instructions": ["nop"]}}
        out = write_function_call_json(
            functions,
            "digraph {}",
            tmp_path / "out.json",
            input_file=binary,
            backend="radare2",
        )
        data = json.loads(out.read_text())
        assert "sha256" in data["meta"]
        assert data["meta"]["file_size"] == 2
        assert data["meta"]["backend"] == "radare2"
