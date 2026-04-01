"""Backend infrastructure for ReverseTool."""

from reverse_tool.backends._base import BackendInfo, BaseBackend

__all__ = ["BackendInfo", "BaseBackend"]


def get_backend(name: str) -> type[BaseBackend]:
    """Get a backend class by name. Uses lazy imports."""
    if name == "ghidra":
        from reverse_tool.backends.ghidra import GhidraBackend

        return GhidraBackend
    elif name == "radare2":
        from reverse_tool.backends.radare2 import Radare2Backend

        return Radare2Backend
    elif name == "null":
        from reverse_tool.backends.null import NullBackend

        return NullBackend
    else:
        available = "ghidra, radare2, null"
        raise ValueError(f"Unknown backend {name!r}. Available: {available}")
