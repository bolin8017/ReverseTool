from pathlib import Path

import pytest

from reverse_tool.backends.null import NullBackend, NullBackendConfig, NullSession
from reverse_tool.engine import TaskResult, collect_files, process_files
from reverse_tool.extractors import BaseExtractor, ExtractResult

pytestmark = pytest.mark.unit


class StubExtractor(BaseExtractor[NullSession]):
    @property
    def name(self) -> str:
        return "stub"

    @property
    def description(self) -> str:
        return "Stub for testing"

    @property
    def supported_backends(self) -> frozenset[str]:
        return frozenset({"null"})

    def extract(self, session, input_file, logger):
        return ExtractResult(
            extractor_name=self.name,
            input_file=input_file,
            data={"opcodes": session.opcodes},
        )

    def write_output(self, result, output_dir):
        out = output_dir / f"{result.input_file.stem}.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text("{}")
        return [out]


class TestCollectFiles:
    def test_collects_files_without_extension(self, tmp_path: Path):
        (tmp_path / "abc123").write_bytes(b"\x00")
        (tmp_path / "def456").write_bytes(b"\x00")
        (tmp_path / "readme.txt").write_text("ignore me")
        files = collect_files(tmp_path)
        names = [f.name for f in files]
        assert "abc123" in names
        assert "def456" in names
        assert "readme.txt" not in names

    def test_collects_with_pattern(self, tmp_path: Path):
        (tmp_path / "mal.exe").write_bytes(b"\x00")
        (tmp_path / "mal.dll").write_bytes(b"\x00")
        (tmp_path / "readme.txt").write_text("ignore")
        files = collect_files(tmp_path, pattern="*.exe")
        assert len(files) == 1
        assert files[0].name == "mal.exe"

    def test_empty_directory(self, tmp_path: Path):
        files = collect_files(tmp_path)
        assert files == []


class TestProcessFiles:
    def test_single_file_success(self, tmp_path: Path):
        binary = tmp_path / "input" / "test_bin"
        binary.parent.mkdir()
        binary.write_bytes(b"\x00")
        output = tmp_path / "output"

        results = list(
            process_files(
                files=[binary],
                backend_cls=NullBackend,
                backend_config=NullBackendConfig(
                    opcodes={"main": ["push", "ret"]},
                ),
                extractor_cls=StubExtractor,
                output_dir=output,
                max_workers=1,
                timeout=60,
            )
        )
        assert len(results) == 1
        assert results[0].success is True
        assert len(results[0].output_files) == 1

    def test_handles_backend_failure(self, tmp_path: Path):
        binary = tmp_path / "test_bin"
        binary.write_bytes(b"\x00")
        output = tmp_path / "output"

        results = list(
            process_files(
                files=[binary],
                backend_cls=NullBackend,
                backend_config=NullBackendConfig(
                    raise_on_open=RuntimeError("crash"),
                ),
                extractor_cls=StubExtractor,
                output_dir=output,
                max_workers=1,
                timeout=60,
            )
        )
        assert len(results) == 1
        assert results[0].success is False
        assert "crash" in results[0].error

    def test_multiple_files(self, tmp_path: Path):
        input_dir = tmp_path / "input"
        input_dir.mkdir()
        for i in range(5):
            (input_dir / f"bin_{i}").write_bytes(b"\x00")
        output = tmp_path / "output"
        files = sorted(input_dir.iterdir())

        results = list(
            process_files(
                files=files,
                backend_cls=NullBackend,
                backend_config=NullBackendConfig(),
                extractor_cls=StubExtractor,
                output_dir=output,
                max_workers=1,
                timeout=60,
            )
        )
        assert len(results) == 5
        assert all(r.success for r in results)

    def test_empty_files_returns_immediately(self, tmp_path: Path):
        results = list(
            process_files(
                files=[],
                backend_cls=NullBackend,
                extractor_cls=StubExtractor,
                output_dir=tmp_path,
            )
        )
        assert results == []

    def test_progress_callback_called(self, tmp_path: Path):
        binary = tmp_path / "bin"
        binary.write_bytes(b"\x00")
        output = tmp_path / "output"

        started: list[int] = []
        completed: list[TaskResult] = []
        finished: list[list[TaskResult]] = []

        class SimpleProgress:
            def on_start(self, total_files: int) -> None:
                started.append(total_files)

            def on_file_complete(self, result: TaskResult) -> None:
                completed.append(result)

            def on_finish(self, results: list[TaskResult]) -> None:
                finished.append(results)

        list(
            process_files(
                files=[binary],
                backend_cls=NullBackend,
                extractor_cls=StubExtractor,
                output_dir=output,
                max_workers=1,
                timeout=60,
                progress=SimpleProgress(),
            )
        )
        assert started == [1]
        assert len(completed) == 1
        assert len(finished) == 1

    def test_manifest_written(self, tmp_path: Path):
        binary = tmp_path / "input" / "test_bin"
        binary.parent.mkdir()
        binary.write_bytes(b"\x00")
        output = tmp_path / "output"

        list(
            process_files(
                files=[binary],
                backend_cls=NullBackend,
                backend_config=NullBackendConfig(),
                extractor_cls=StubExtractor,
                output_dir=output,
                max_workers=1,
                timeout=60,
            )
        )
        manifest = output / "manifest.jsonl"
        assert manifest.exists()
        import json

        entry = json.loads(manifest.read_text().strip())
        assert entry["status"] == "success"
        assert "cpu_time_sec" in entry
        assert "wall_time_sec" in entry
