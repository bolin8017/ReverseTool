"""Parallel processing engine for ReverseTool."""

from __future__ import annotations

import fnmatch
import logging
import os
from collections.abc import Iterator
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import UTC
from pathlib import Path
from typing import Any, Protocol

from reverse_tool.backends._base import BaseBackend
from reverse_tool.extractors._base import BaseExtractor

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class TaskResult:
    """Result of processing a single binary file."""

    input_file: Path
    success: bool
    output_files: list[Path] = field(default_factory=list)
    error: str | None = None
    cpu_time: float = 0.0
    wall_time: float = 0.0


class ProgressCallback(Protocol):
    """Protocol for progress reporting. CLI layer injects implementation."""

    def on_start(self, total_files: int) -> None: ...
    def on_file_complete(self, result: TaskResult) -> None: ...
    def on_finish(self, results: list[TaskResult]) -> None: ...


def collect_files(directory: Path, *, pattern: str | None = None) -> list[Path]:
    """Collect binary files from directory.

    Args:
        directory: Root directory to scan.
        pattern: Glob pattern. Default (None) matches files without extensions.

    Returns:
        Sorted list of file paths.
    """
    files = []
    for root, _, filenames in os.walk(directory):
        for filename in filenames:
            if pattern:
                if not fnmatch.fnmatch(filename, pattern):
                    continue
            else:
                if "." in filename:
                    continue
            files.append(Path(root) / filename)
    files.sort()
    return files


def _process_single_file(
    input_file: Path,
    backend_cls: type[BaseBackend],
    backend_config: Any,
    extractor_cls: type[BaseExtractor],
    output_dir: Path,
    timeout: int,
) -> TaskResult:
    """Worker function. Runs in a separate process.

    Receives classes (not instances) because classes are picklable.
    Each worker creates its own backend + extractor + session.
    """
    import time

    log = logging.getLogger(f"worker.{input_file.stem}")
    wall_start = time.perf_counter()
    cpu_start = time.process_time()

    try:
        backend = (
            backend_cls(backend_config)  # type: ignore[call-arg]
            if backend_config is not None
            else backend_cls()
        )
        extractor = extractor_cls()

        with backend.session(input_file, timeout=timeout) as session:
            result = extractor.extract(session, input_file, log)
            file_output_dir = output_dir / input_file.stem
            file_output_dir.mkdir(parents=True, exist_ok=True)
            written = extractor.write_output(result, file_output_dir)

        cpu_time = time.process_time() - cpu_start
        wall_time = time.perf_counter() - wall_start
        return TaskResult(
            input_file=input_file,
            success=True,
            output_files=written,
            cpu_time=cpu_time,
            wall_time=wall_time,
        )
    except Exception as exc:
        cpu_time = time.process_time() - cpu_start
        wall_time = time.perf_counter() - wall_start
        log.error("Failed to process %s: %s", input_file, exc, exc_info=True)
        return TaskResult(
            input_file=input_file,
            success=False,
            error=str(exc),
            cpu_time=cpu_time,
            wall_time=wall_time,
        )


def process_files(
    files: list[Path],
    backend_cls: type[BaseBackend],
    extractor_cls: type[BaseExtractor],
    output_dir: Path,
    *,
    backend_config: Any = None,
    max_workers: int | None = None,
    timeout: int = 600,
    progress: ProgressCallback | None = None,
) -> Iterator[TaskResult]:
    """Process files, yielding results as they complete.

    Uses sequential processing when max_workers=1 or there is only
    one file (easier debugging).
    Uses ProcessPoolExecutor otherwise (CPU-bound, process isolation).
    """
    if not files:
        return

    if progress:
        progress.on_start(len(files))

    results: list[TaskResult] = []

    try:
        if max_workers == 1 or len(files) == 1:
            for f in files:
                result = _process_single_file(
                    f,
                    backend_cls,
                    backend_config,
                    extractor_cls,
                    output_dir,
                    timeout,
                )
                results.append(result)
                if progress:
                    progress.on_file_complete(result)
                yield result
        else:
            workers = max_workers or min(os.cpu_count() or 1, len(files))
            with ProcessPoolExecutor(max_workers=workers) as pool:
                future_to_file = {
                    pool.submit(
                        _process_single_file,
                        f,
                        backend_cls,
                        backend_config,
                        extractor_cls,
                        output_dir,
                        timeout,
                    ): f
                    for f in files
                }
                for future in as_completed(future_to_file):
                    try:
                        result = future.result()
                    except Exception as exc:
                        f = future_to_file[future]
                        logger.error("Worker crashed for %s: %s", f, exc)
                        result = TaskResult(
                            input_file=f, success=False, error=f"Worker crash: {exc}"
                        )
                    results.append(result)
                    if progress:
                        progress.on_file_complete(result)
                    yield result
    finally:
        if progress:
            progress.on_finish(results)
        # Overwrite mode — each extraction run produces its own manifest
        _write_manifest(results, output_dir)


def _write_manifest(results: list[TaskResult], output_dir: Path) -> None:
    """Write manifest.jsonl summarizing the extraction run."""
    import json
    from datetime import datetime

    manifest_path = output_dir / "manifest.jsonl"
    output_dir.mkdir(parents=True, exist_ok=True)

    with open(manifest_path, "w", encoding="utf-8") as f:
        for r in results:
            entry = {
                "file_name": r.input_file.name,
                "file_path": str(r.input_file),
                "status": "success" if r.success else "error",
                "cpu_time_sec": round(r.cpu_time, 4),
                "wall_time_sec": round(r.wall_time, 4),
                "output_files": [str(p) for p in r.output_files],
                "timestamp": datetime.now(tz=UTC).isoformat(),
            }
            if r.error:
                entry["error"] = r.error
            f.write(json.dumps(entry, separators=(",", ":")) + "\n")
