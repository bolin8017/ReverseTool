import json

import pytest

from reverse_tool.extractors.function_call._writer import write_functions_json

pytestmark = pytest.mark.unit


class TestJSONWriter:
    def test_writes_valid_json(self, tmp_path):
        functions = {
            "0x1000": {"function_name": "main", "instructions": ["push", "ret"]},
        }
        out = write_functions_json(functions, tmp_path / "funcs.json")
        assert out.exists()
        parsed = json.loads(out.read_text())
        assert parsed["0x1000"]["function_name"] == "main"

    def test_round_trip(self, tmp_path):
        data = {"0x1": {"name": "a", "calls": ["b"]}}
        out = write_functions_json(data, tmp_path / "rt.json")
        assert json.loads(out.read_text()) == data
