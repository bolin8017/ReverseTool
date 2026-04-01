"""Parallel processing engine for ReverseTool."""

from __future__ import annotations

import fnmatch
import logging
import os
from collections.abc import Iterator
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import dataclass, field
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
    elapsed: float = 0.0


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
    start = time.perf_counter()

    try:
        backend = (
            backend_cls(backend_config)  # type: ignore[call-arg]
            if backend_config is not None
            else backend_cls()
        )
        backend.validate_environment()
        extractor = extractor_cls()

        with backend.session(input_file, timeout=timeout) as session:
            result = extractor.extract(session, input_file, log)
            file_output_dir = output_dir / input_file.stem
            file_output_dir.mkdir(parents=True, exist_ok=True)
            written = extractor.write_output(result, file_output_dir)

        elapsed = time.perf_counter() - start
        return TaskResult(
            input_file=input_file,
            success=True,
            output_files=written,
            elapsed=elapsed,
        )
    except Exception as exc:
        elapsed = time.perf_counter() - start
        log.error("Failed to process %s: %s", input_file, exc)
        return TaskResult(
            input_file=input_file,
            success=False,
            error=str(exc),
            elapsed=elapsed,
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

    Uses sequential processing when max_workers=1 (easier debugging).
    Uses ProcessPoolExecutor otherwise (CPU-bound, process isolation).
    """
    if not files:
        return

    if progress:
        progress.on_start(len(files))

    results: list[TaskResult] = []

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
                result = future.result()
                results.append(result)
                if progress:
                    progress.on_file_complete(result)
                yield result

    if progress:
        progress.on_finish(results)
