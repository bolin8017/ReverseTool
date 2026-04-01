from unittest.mock import patch

import pytest
from click.testing import CliRunner

from reverse_tool.cli import cli

pytestmark = pytest.mark.unit


@pytest.fixture
def runner():
    return CliRunner()


class TestCLI:
    def test_help(self, runner):
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        output_lower = result.output.lower()
        assert "reverse-tool" in output_lower or "usage" in output_lower

    def test_version(self, runner):
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "1.0.0" in result.output

    def test_backends_command(self, runner):
        result = runner.invoke(cli, ["backends"])
        assert result.exit_code == 0
        assert "ghidra" in result.output.lower()
        assert "radare2" in result.output.lower()

    def test_doctor_command(self, runner):
        result = runner.invoke(cli, ["doctor"])
        assert result.exit_code == 0
        assert "python" in result.output.lower()

    def test_unknown_subcommand(self, runner):
        result = runner.invoke(cli, ["nonexistent"])
        assert result.exit_code != 0

    def test_opcode_help(self, runner):
        result = runner.invoke(cli, ["opcode", "--help"])
        assert result.exit_code == 0
        assert "--backend" in result.output or "-b" in result.output

    def test_function_call_help(self, runner):
        result = runner.invoke(cli, ["function-call", "--help"])
        assert result.exit_code == 0
        assert "--backend" in result.output or "-b" in result.output

    def test_opcode_missing_required(self, runner):
        result = runner.invoke(cli, ["opcode"])
        assert result.exit_code != 0

    def test_backends_command_includes_idapro(self, runner):
        result = runner.invoke(cli, ["backends"])
        assert result.exit_code == 0
        assert "idapro" in result.output.lower()

    def test_doctor_command_includes_idapro(self, runner):
        result = runner.invoke(cli, ["doctor"])
        assert result.exit_code == 0
        assert "ida" in result.output.lower()

    def test_config_fallback_for_ida_path(self, runner, tmp_path):
        """Config file idapro_path is used when --ida-path not provided."""
        from reverse_tool.config import Config

        config = Config(idapro_path="/opt/idapro/idat")
        bindir = tmp_path / "bins"
        bindir.mkdir()
        (bindir / "sample").write_bytes(b"\x00")

        with patch("reverse_tool.config.load_config", return_value=config):
            # Will fail at validate_environment (idat not found at path),
            # but proves config was loaded and used as fallback
            result = runner.invoke(cli, ["opcode", "-b", "idapro", "-d", str(bindir)])
        assert "idat not found at /opt/idapro/idat" in result.output

    def test_config_fallback_for_ghidra_path(self, runner, tmp_path):
        """Config file ghidra_path is used when --ghidra-path not provided."""
        from reverse_tool.config import Config

        config = Config(ghidra_path="/opt/ghidra/analyzeHeadless")
        bindir = tmp_path / "bins"
        bindir.mkdir()
        (bindir / "sample").write_bytes(b"\x00")

        with patch("reverse_tool.config.load_config", return_value=config):
            result = runner.invoke(cli, ["opcode", "-b", "ghidra", "-d", str(bindir)])
        assert "not found at /opt/ghidra/analyzeHeadless" in result.output
