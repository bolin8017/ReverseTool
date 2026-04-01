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
        assert "0.1.0" in result.output

    def test_backends_command(self, runner):
        result = runner.invoke(cli, ["backends"])
        assert result.exit_code == 0
        assert "null" in result.output.lower()

    def test_doctor_command(self, runner):
        result = runner.invoke(cli, ["doctor"])
        assert result.exit_code == 0
        assert "python" in result.output.lower()

    def test_unknown_subcommand(self, runner):
        result = runner.invoke(cli, ["nonexistent"])
        assert result.exit_code != 0
