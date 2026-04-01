from unittest.mock import patch

import pytest

from reverse_tool.backends.ghidra import GhidraBackend, GhidraSession
from reverse_tool.exceptions import BackendNotAvailable

pytestmark = pytest.mark.unit


class TestGhidraBackend:
    def test_info(self):
        backend = GhidraBackend(ghidra_path="/fake/path")
        assert backend.info.name == "ghidra"

    def test_info_default_version(self):
        backend = GhidraBackend()
        assert "12.0" in backend.info.version

    def test_info_version_after_detection(self, tmp_path):
        # Create fake Ghidra installation with version file
        support = tmp_path / "support"
        support.mkdir()
        analyze = support / "analyzeHeadless"
        analyze.write_text("#!/bin/bash\n")
        analyze.chmod(0o755)

        ghidra_dir = tmp_path / "Ghidra"
        ghidra_dir.mkdir()
        props = ghidra_dir / "application.properties"
        props.write_text("application.version=12.0.4\n")

        backend = GhidraBackend(ghidra_path=str(analyze))
        backend.validate_environment()
        assert backend.info.version == "12.0.4"

    def test_version_check_fails_for_old_version(self, tmp_path):
        from reverse_tool.exceptions import BackendVersionError

        support = tmp_path / "support"
        support.mkdir()
        analyze = support / "analyzeHeadless"
        analyze.write_text("#!/bin/bash\n")
        analyze.chmod(0o755)

        ghidra_dir = tmp_path / "Ghidra"
        ghidra_dir.mkdir()
        props = ghidra_dir / "application.properties"
        props.write_text("application.version=11.0.0\n")

        backend = GhidraBackend(ghidra_path=str(analyze))
        with pytest.raises(BackendVersionError) as exc_info:
            backend.validate_environment()
        assert exc_info.value.found == "11.0.0"

    def test_version_check_skips_when_no_properties(self, tmp_path):
        support = tmp_path / "support"
        support.mkdir()
        analyze = support / "analyzeHeadless"
        analyze.write_text("#!/bin/bash\n")
        analyze.chmod(0o755)
        # No Ghidra/application.properties — should proceed without error
        backend = GhidraBackend(ghidra_path=str(analyze))
        backend.validate_environment()

    def test_validate_finds_on_path(self, tmp_path):
        analyze = tmp_path / "analyzeHeadless"
        analyze.write_text("#!/bin/bash\n")
        analyze.chmod(0o755)

        backend = GhidraBackend()
        with patch(
            "reverse_tool.backends.ghidra.shutil.which",
            return_value=str(analyze),
        ):
            backend.validate_environment()
        assert backend.ghidra_path is not None

    def test_validate_raises_when_not_found(self):
        backend = GhidraBackend()
        with (
            patch("reverse_tool.backends.ghidra.shutil.which", return_value=None),
            pytest.raises(BackendNotAvailable),
        ):
            backend.validate_environment()

    def test_validate_missing_path_raises(self):
        backend = GhidraBackend(ghidra_path="/nonexistent/analyzeHeadless")
        with pytest.raises(BackendNotAvailable):
            backend.validate_environment()

    def test_session_returns_ghidra_session(self, tmp_path):
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

    def test_open_session_raises_without_validate(self):
        backend = GhidraBackend()
        with pytest.raises(BackendNotAvailable):
            backend._open_session(None, 300)

    def test_close_session_noop(self, tmp_path):
        fake = tmp_path / "analyzeHeadless"
        fake.touch()
        backend = GhidraBackend(ghidra_path=str(fake))
        session = GhidraSession(
            ghidra_path=fake, input_file=tmp_path / "bin", timeout=300
        )
        backend._close_session(session)  # should not raise
