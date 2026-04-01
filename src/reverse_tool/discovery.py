"""Extractor auto-discovery and registration."""

from __future__ import annotations

import importlib
import logging
import pkgutil
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from reverse_tool.extractors._base import BaseExtractor

logger = logging.getLogger(__name__)

_EXTRACTOR_REGISTRY: dict[str, type[BaseExtractor]] = {}


def _register_extractor(cls: type[BaseExtractor]) -> None:
    """Called by BaseExtractor.__init_subclass__. Internal API."""
    name = cls.name.fget(cls)  # type: ignore[attr-defined]
    if name in _EXTRACTOR_REGISTRY:
        existing = _EXTRACTOR_REGISTRY[name]
        if existing is not cls:
            raise ImportError(
                f"Duplicate extractor name {name!r}: "
                f"{cls!r} conflicts with {existing!r}"
            )
        return
    _EXTRACTOR_REGISTRY[name] = cls
    logger.debug("Registered extractor: %s (%s)", name, cls.__module__)


def discover_extractors() -> dict[str, type[BaseExtractor]]:
    """Import all extractor subpackages to trigger __init_subclass__ registration.

    Returns:
        Dict mapping extractor names to their classes.
    """
    import reverse_tool.extractors as ext_pkg

    for _finder, module_name, _is_pkg in pkgutil.walk_packages(
        ext_pkg.__path__, prefix=ext_pkg.__name__ + "."
    ):
        try:
            importlib.import_module(module_name)
        except ImportError as e:
            logger.warning("Skipping %s: %s", module_name, e)

    return dict(_EXTRACTOR_REGISTRY)


def get_extractor(name: str) -> type[BaseExtractor]:
    """Get a single extractor by name.

    Raises:
        KeyError: If extractor name is not found.
    """
    registry = discover_extractors()
    try:
        return registry[name]
    except KeyError:
        available = ", ".join(sorted(registry)) or "(none)"
        raise KeyError(f"Unknown extractor {name!r}. Available: {available}") from None
