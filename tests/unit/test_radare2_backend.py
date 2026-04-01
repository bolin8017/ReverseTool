import pytest

from reverse_tool.backends import get_backend
from reverse_tool.backends.radare2 import Radare2Backend

pytestmark = pytest.mark.unit


class TestRadare2BackendUnit:
    def test_info(self):
        backend = Radare2Backend()
        assert backend.info.name == "radare2"

    def test_get_backend_returns_correct_classes(self):
        assert get_backend("null").__name__ == "NullBackend"
        assert get_backend("ghidra").__name__ == "GhidraBackend"
        assert get_backend("radare2").__name__ == "Radare2Backend"

    def test_get_backend_unknown_raises(self):
        with pytest.raises(ValueError, match="Unknown backend"):
            get_backend("ida")
