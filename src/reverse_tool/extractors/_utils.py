"""Shared utilities for extractors."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any


def compute_file_hash(file_path: Path) -> dict[str, str]:
    """Compute SHA256 and MD5 of a file."""
    sha256 = hashlib.sha256()
    md5 = hashlib.md5()  # noqa: S324
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
            md5.update(chunk)
    return {"sha256": sha256.hexdigest(), "md5": md5.hexdigest()}


def build_output_metadata(
    *,
    extractor: str,
    backend: str,
    input_file: Path | None = None,
    **extra: Any,
) -> dict[str, Any]:
    """Build standard metadata dict for output files."""
    meta: dict[str, Any] = {"extractor": extractor, "backend": backend, **extra}
    if input_file and input_file.exists():
        hashes = compute_file_hash(input_file)
        meta.update(
            file_name=input_file.name,
            file_size=input_file.stat().st_size,
            sha256=hashes["sha256"],
            md5=hashes["md5"],
        )
    return meta
