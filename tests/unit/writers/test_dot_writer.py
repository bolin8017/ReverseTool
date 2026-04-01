import pytest

from reverse_tool.extractors.function_call._writer import write_dot

pytestmark = pytest.mark.unit


class TestDOTWriter:
    def test_writes_dot_content(self, tmp_path):
        content = 'digraph code {\n  "0x1000" -> "0x2000";\n}'
        out = write_dot(content, tmp_path / "graph.dot")
        assert out.exists()
        assert out.read_text() == content

    def test_creates_parent_dirs(self, tmp_path):
        out = write_dot("digraph {}", tmp_path / "deep" / "graph.dot")
        assert out.exists()
