import csv
from pathlib import Path

import pytest

from reverse_tool.extractors.opcode._writer import write_opcode_csv

pytestmark = pytest.mark.unit


class TestCSVWriter:
    def test_writes_header_and_rows(self, tmp_path: Path):
        opcodes = [
            {"addr": 4194356, "opcode": "nop", "section_name": ".text"},
            {"addr": 4194360, "opcode": "mov", "section_name": ".text"},
        ]
        out = write_opcode_csv(opcodes, tmp_path / "out.csv")
        assert out.exists()

        with open(out, encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        assert len(rows) == 2
        assert rows[0]["opcode"] == "nop"
        assert rows[1]["addr"] == "4194360"

    def test_empty_opcodes_writes_header_only(self, tmp_path: Path):
        out = write_opcode_csv([], tmp_path / "empty.csv")
        with open(out, encoding="utf-8") as f:
            lines = f.read().strip().splitlines()
        assert len(lines) == 1
        assert "addr" in lines[0]

    def test_creates_parent_dirs(self, tmp_path: Path):
        out = write_opcode_csv(
            [{"addr": 1, "opcode": "ret", "section_name": ".text"}],
            tmp_path / "deep" / "nested" / "out.csv",
        )
        assert out.exists()
