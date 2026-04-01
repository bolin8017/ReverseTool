from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from reverse_tool.backends import BackendInfo, BaseBackend
from reverse_tool.backends.null import NullBackend, NullBackendConfig

pytestmark = pytest.mark.unit


class TestBackendInfo:
    def test_is_frozen_dataclass(self):
        info = BackendInfo(name="test", version="1.0")
        assert info.name == "test"
        assert info.version == "1.0"
        with pytest.raises(FrozenInstanceError):
            info.name = "other"


class ConcreteBackend(BaseBackend[str]):
    @property
    def info(self) -> BackendInfo:
        return BackendInfo(name="concrete", version="1.0")

    def validate_environment(self) -> None:
        pass

    def _open_session(self, input_file: Path, timeout: int) -> str:
        return f"session:{input_file}"

    def _close_session(self, session: str) -> None:
        pass


class TestBaseBackend:
    def test_session_context_manager(self, tmp_path: Path):
        binary = tmp_path / "test.bin"
        binary.write_bytes(b"\x00")
        backend = ConcreteBackend()

        with backend.session(binary, timeout=60) as session:
            assert session == f"session:{binary}"

    def test_session_closes_on_exception(self, tmp_path: Path):
        class TrackingBackend(BaseBackend[str]):
            closed = False

            @property
            def info(self) -> BackendInfo:
                return BackendInfo(name="tracking", version="1.0")

            def validate_environment(self) -> None:
                pass

            def _open_session(self, input_file: Path, timeout: int) -> str:
                return "open"

            def _close_session(self, session: str) -> None:
                TrackingBackend.closed = True

        backend = TrackingBackend()
        binary = tmp_path / "test.bin"
        binary.write_bytes(b"\x00")

        with pytest.raises(RuntimeError), backend.session(binary):
            raise RuntimeError("crash")

        assert TrackingBackend.closed is True

    def test_cannot_instantiate_abstract(self):
        with pytest.raises(TypeError):
            BaseBackend()


class TestNullBackend:
    def test_returns_configured_data(self, tmp_path: Path):
        config = NullBackendConfig(
            functions={"main": {"addr": 0x1000, "calls": ["exit"]}},
            opcodes={"main": ["push", "mov", "ret"]},
        )
        backend = NullBackend(config)
        binary = tmp_path / "test.bin"
        binary.write_bytes(b"\x00")

        with backend.session(binary) as session:
            assert session.functions == config.functions
            assert session.opcodes == config.opcodes

    def test_default_config_returns_empty(self, tmp_path: Path):
        backend = NullBackend()
        binary = tmp_path / "test.bin"
        binary.write_bytes(b"\x00")

        with backend.session(binary) as session:
            assert session.functions == {}
            assert session.opcodes == {}

    def test_simulate_failure(self, tmp_path: Path):
        config = NullBackendConfig(
            raise_on_open=RuntimeError("Ghidra crashed"),
        )
        backend = NullBackend(config)
        binary = tmp_path / "test.bin"
        binary.write_bytes(b"\x00")

        with (
            pytest.raises(RuntimeError, match="Ghidra crashed"),
            backend.session(binary),
        ):
            pass

    def test_validate_environment_always_passes(self):
        backend = NullBackend()
        backend.validate_environment()  # should not raise

    def test_info(self):
        backend = NullBackend()
        assert backend.info.name == "null"
        assert backend.info.version == "0.0.0"
