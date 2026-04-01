from pathlib import Path

import pytest

from reverse_tool.backends._base import BackendInfo
from reverse_tool.extractors import BaseExtractor, ExtractResult

pytestmark = pytest.mark.unit


class TestExtractResult:
    def test_is_frozen(self):
        result = ExtractResult(
            extractor_name="test",
            input_file=Path("/tmp/test"),
            data={"key": "val"},
        )
        assert result.extractor_name == "test"
        assert result.metadata == {}


class TestBaseExtractor:
    def test_cannot_instantiate_abstract(self):
        with pytest.raises(TypeError):
            BaseExtractor()

    def test_concrete_extractor_registered(self):
        """Concrete subclasses auto-register via __init_subclass__."""
        from reverse_tool.discovery import _EXTRACTOR_REGISTRY

        class DummyExtractor(BaseExtractor):
            @property
            def name(self) -> str:
                return "dummy_test"

            @property
            def description(self) -> str:
                return "Test extractor"

            @property
            def supported_backends(self) -> frozenset[str]:
                return frozenset({"null"})

            def extract(self, session, input_file, logger):
                return ExtractResult(
                    extractor_name=self.name,
                    input_file=input_file,
                    data={},
                )

            def write_output(self, result, output_dir):
                return []

        assert "dummy_test" in _EXTRACTOR_REGISTRY

    def test_supports_backend(self):
        class CheckExtractor(BaseExtractor):
            @property
            def name(self) -> str:
                return "check_test"

            @property
            def description(self) -> str:
                return "Check"

            @property
            def supported_backends(self) -> frozenset[str]:
                return frozenset({"ghidra", "radare2", "idapro"})

            def extract(self, session, input_file, logger):
                return ExtractResult(
                    extractor_name=self.name, input_file=input_file, data={}
                )

            def write_output(self, result, output_dir):
                return []

        ext = CheckExtractor()

        class FakeBackend:
            info = BackendInfo(name="ghidra", version="12.0.4")

        assert ext.supports_backend(FakeBackend()) is True

        class FakeBackend2:
            info = BackendInfo(name="ida", version="8.0")

        assert ext.supports_backend(FakeBackend2()) is False
