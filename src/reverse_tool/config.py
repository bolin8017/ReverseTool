"""Configuration loading for ReverseTool."""

from __future__ import annotations

import logging
import tomllib
from dataclasses import dataclass
from pathlib import Path

from reverse_tool.exceptions import ConfigError

logger = logging.getLogger(__name__)

DEFAULT_CONFIG_PATH = Path.home() / ".config" / "reverse-tool" / "config.toml"


@dataclass
class Config:
    """Resolved configuration values."""

    default_backend: str | None = None
    timeout: int = 600
    max_workers: int | None = None
    ghidra_path: str | None = None
    radare2_analysis_level: str = "aa"
    idapro_path: str | None = None


def load_config(path: Path = DEFAULT_CONFIG_PATH) -> Config:
    """Load configuration from TOML file.

    Returns default Config if file does not exist.
    Raises ConfigError on malformed TOML.
    """
    if not path.is_file():
        logger.debug("Config file not found: %s", path)
        return Config()

    try:
        with open(path, "rb") as f:
            data = tomllib.load(f)
    except tomllib.TOMLDecodeError as e:
        raise ConfigError(f"Invalid TOML in {path}: {e}") from e
    except OSError as e:
        raise ConfigError(f"Cannot read config file {path}: {e}") from e

    defaults = data.get("defaults", {})
    ghidra = data.get("backends", {}).get("ghidra", {})
    radare2 = data.get("backends", {}).get("radare2", {})
    idapro = data.get("backends", {}).get("idapro", {})

    return Config(
        default_backend=defaults.get("backend"),
        timeout=defaults.get("timeout", 600),
        max_workers=defaults.get("max_workers"),
        ghidra_path=ghidra.get("path"),
        radare2_analysis_level=radare2.get("analysis_level", "aa"),
        idapro_path=idapro.get("path"),
    )
