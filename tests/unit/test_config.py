from pathlib import Path

import pytest

from reverse_tool.config import Config, load_config

pytestmark = pytest.mark.unit


class TestConfig:
    def test_default_config(self):
        config = Config()
        assert config.default_backend is None
        assert config.timeout == 600
        assert config.ghidra_path is None

    def test_load_from_toml(self, tmp_path: Path):
        toml_file = tmp_path / "config.toml"
        toml_file.write_text("""\
[defaults]
backend = "ghidra"
timeout = 1200

[backends.ghidra]
path = "/opt/ghidra/support/analyzeHeadless"
""")
        config = load_config(toml_file)
        assert config.default_backend == "ghidra"
        assert config.timeout == 1200
        assert config.ghidra_path == "/opt/ghidra/support/analyzeHeadless"

    def test_missing_file_returns_default(self):
        config = load_config(Path("/nonexistent/config.toml"))
        assert config.default_backend is None

    def test_malformed_toml_raises_config_error(self, tmp_path: Path):
        toml_file = tmp_path / "bad.toml"
        toml_file.write_text("[[invalid toml content!!")
        from reverse_tool.exceptions import ConfigError

        with pytest.raises(ConfigError):
            load_config(toml_file)

    def test_default_idapro_path_is_none(self):
        config = Config()
        assert config.idapro_path is None

    def test_load_idapro_from_toml(self, tmp_path: Path):
        toml_file = tmp_path / "config.toml"
        toml_file.write_text("""\
[backends.idapro]
path = "/opt/idapro/idat"
""")
        config = load_config(toml_file)
        assert config.idapro_path == "/opt/idapro/idat"
