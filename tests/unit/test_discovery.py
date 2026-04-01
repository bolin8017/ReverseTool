import pytest

from reverse_tool.discovery import (
    _EXTRACTOR_REGISTRY,
    discover_extractors,
    get_extractor,
)
from reverse_tool.extractors import BaseExtractor, ExtractResult

pytestmark = pytest.mark.unit


# Module-level extractor: registered automatically via __init_subclass__
class _DiscoveryTestExtractor(BaseExtractor):
    @property
    def name(self) -> str:
        return "_discovery_test_sentinel"

    @property
    def description(self) -> str:
        return "Sentinel extractor for discovery tests"

    @property
    def supported_backends(self) -> frozenset[str]:
        return frozenset({"null"})

    def extract(self, session, input_file, logger):
        return ExtractResult(extractor_name=self.name, input_file=input_file, data={})

    def write_output(self, result, output_dir):
        return []


class TestDiscovery:
    def test_discover_returns_dict(self):
        result = discover_extractors()
        assert isinstance(result, dict)

    def test_get_extractor_unknown_raises_key_error(self):
        with pytest.raises(KeyError, match="Unknown extractor"):
            get_extractor("nonexistent_extractor_xyz")

    def test_registry_is_populated_by_subclassing(self):
        """Extractors defined in test_extractors.py should be in registry."""
        # Import to trigger registration
        import tests.unit.test_extractors  # noqa: F401

        # Sentinel defined at module level of this file is always registered
        assert "_discovery_test_sentinel" in _EXTRACTOR_REGISTRY
