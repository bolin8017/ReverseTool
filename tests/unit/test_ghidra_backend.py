import pytest

from reverse_tool.backends.ghidra import GhidraBackend, GhidraSession
from reverse_tool.exceptions import BackendNotAvailable

pytestmark = pytest.mark.unit


class TestGhidraBackend:
    def test_info(self):
        backend = GhidraBackend(ghidra_path="/fake/path")
        assert backend.info.name == "ghidra"

    def test_validate_missing_path_raises(self):
        backend = GhidraBackend(ghidra_path="/nonexistent/analyzeHeadless")
        with pytest.raises(BackendNotAvailable):
            backend.validate_environment()

    def test_session_returns_ghidra_session(self, tmp_path):
        # Create a fake analyzeHeadless
        fake_ghidra = tmp_path / "analyzeHeadless"
        fake_ghidra.write_text("#!/bin/bash\n")
        fake_ghidra.chmod(0o755)

        binary = tmp_path / "test.bin"
        binary.write_bytes(b"\x00")

        backend = GhidraBackend(ghidra_path=str(fake_ghidra))
        with backend.session(binary, timeout=60) as session:
            assert isinstance(session, GhidraSession)
            assert session.ghidra_path == fake_ghidra
            assert session.input_file == binary
            assert session.timeout == 60
