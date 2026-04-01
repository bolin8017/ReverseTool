from unittest.mock import patch

import pytest

from reverse_tool.backends import get_backend
from reverse_tool.backends._base import BackendInfo

pytestmark = pytest.mark.unit


class TestIdaproBackend:
    def test_get_backend_returns_idapro(self):
        cls = get_backend("idapro")
        from reverse_tool.backends.idapro import IdaproBackend

        assert cls is IdaproBackend

    def test_info(self):
        from reverse_tool.backends.idapro import IdaproBackend

        backend = IdaproBackend()
        info = backend.info
        assert isinstance(info, BackendInfo)
        assert info.name == "idapro"

    def test_info_version_after_detection(self, tmp_path):
        from reverse_tool.backends.idapro import IdaproBackend

        # Create fake IDA installation with version file
        idat = tmp_path / "idat"
        idat.touch()
        python_dir = tmp_path / "python"
        python_dir.mkdir()
        ida_pro_py = python_dir / "ida_pro.py"
        ida_pro_py.write_text('IDA_SDK_VERSION = 930\n"""IDA SDK v9.3.\n"""\n')

        backend = IdaproBackend(str(idat))
        backend.validate_environment()
        assert backend.info.version == "9.3"

    def test_init_with_path(self):
        from reverse_tool.backends.idapro import IdaproBackend

        backend = IdaproBackend("/usr/local/bin/idat")
        assert backend.ida_path is not None

    def test_init_without_path(self):
        from reverse_tool.backends.idapro import IdaproBackend

        backend = IdaproBackend()
        assert backend.ida_path is None

    def test_validate_finds_idat_on_path(self, tmp_path):
        from reverse_tool.backends.idapro import IdaproBackend

        idat = tmp_path / "idat"
        idat.touch()
        backend = IdaproBackend()
        with patch("reverse_tool.backends.idapro.shutil.which", return_value=str(idat)):
            backend.validate_environment()
        assert backend.ida_path is not None

    def test_validate_raises_when_not_found(self):
        from reverse_tool.backends.idapro import IdaproBackend
        from reverse_tool.exceptions import BackendNotAvailable

        backend = IdaproBackend()
        with (
            patch("reverse_tool.backends.idapro.shutil.which", return_value=None),
            pytest.raises(BackendNotAvailable) as exc_info,
        ):
            backend.validate_environment()
        assert "idapro" in str(exc_info.value)

    def test_validate_raises_when_path_missing(self, tmp_path):
        from reverse_tool.backends.idapro import IdaproBackend
        from reverse_tool.exceptions import BackendNotAvailable

        backend = IdaproBackend(str(tmp_path / "nonexistent" / "idat"))
        with pytest.raises(BackendNotAvailable):
            backend.validate_environment()

    def test_version_check_passes_for_valid_version(self, tmp_path):
        from reverse_tool.backends.idapro import IdaproBackend

        idat = tmp_path / "idat"
        idat.touch()
        python_dir = tmp_path / "python"
        python_dir.mkdir()
        ida_pro_py = python_dir / "ida_pro.py"
        ida_pro_py.write_text('"""IDA SDK v9.3.\n"""\n')

        backend = IdaproBackend(str(idat))
        backend.validate_environment()  # should not raise

    def test_version_check_fails_for_old_version(self, tmp_path):
        from reverse_tool.backends.idapro import IdaproBackend
        from reverse_tool.exceptions import BackendVersionError

        idat = tmp_path / "idat"
        idat.touch()
        python_dir = tmp_path / "python"
        python_dir.mkdir()
        ida_pro_py = python_dir / "ida_pro.py"
        ida_pro_py.write_text('"""IDA SDK v8.4.\n"""\n')

        backend = IdaproBackend(str(idat))
        with pytest.raises(BackendVersionError) as exc_info:
            backend.validate_environment()
        assert exc_info.value.found == "8.4"
        assert "9.3" in exc_info.value.expected

    def test_version_check_skips_when_no_python_dir(self, tmp_path):
        from reverse_tool.backends.idapro import IdaproBackend

        idat = tmp_path / "idat"
        idat.touch()
        # No python/ directory — version check should be skipped gracefully
        backend = IdaproBackend(str(idat))
        backend.validate_environment()  # should not raise

    def test_required_version_constant(self):
        from reverse_tool.backends.idapro import IdaproBackend

        assert IdaproBackend.REQUIRED_VERSION == "9.3"

    def test_open_session(self, tmp_path):
        from reverse_tool.backends.idapro import IdaproBackend, IdaproSession

        idat = tmp_path / "idat"
        idat.touch()
        binary = tmp_path / "test_bin"
        binary.write_bytes(b"\x00")

        backend = IdaproBackend(str(idat))
        session = backend._open_session(binary, timeout=300)
        assert isinstance(session, IdaproSession)
        assert session.input_file == binary
        assert session.timeout == 300
        assert session.ida_path == idat

    def test_open_session_raises_without_validate(self):
        from reverse_tool.backends.idapro import IdaproBackend
        from reverse_tool.exceptions import BackendNotAvailable

        backend = IdaproBackend()
        with pytest.raises(BackendNotAvailable):
            backend._open_session(None, 300)

    def test_close_session_noop(self, tmp_path):
        from reverse_tool.backends.idapro import IdaproBackend, IdaproSession

        idat = tmp_path / "idat"
        idat.touch()
        backend = IdaproBackend(str(idat))
        session = IdaproSession(ida_path=idat, input_file=tmp_path / "bin", timeout=300)
        backend._close_session(session)  # should not raise
