# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [1.0.0] - 2026-04-02

### Added

- **Core Framework**
  - `BaseBackend` abstract class with Generic session typing and context manager
  - `BaseExtractor` abstract class with `__init_subclass__` auto-registration
  - `NullBackend` programmable testing backend
  - Parallel processing engine with `ProcessPoolExecutor` and `ProgressCallback`
  - Extractor auto-discovery via `pkgutil` scanning
  - TOML configuration loading (`~/.config/reverse-tool/config.toml`)
  - `config.toml` integration in CLI (backend paths, defaults, analysis options)
  - Structured exception hierarchy (`ReverseToolError`, `BackendError`, etc.)

- **Backends**
  - `GhidraBackend` -- Ghidra 12.0.4 headless analyzer integration
  - `Radare2Backend` -- Radare2 6.1.2 via r2pipe with pre-flight timeout check
  - `IdaproBackend` -- IDA Pro 9.3+ headless analysis via idat

- **Extractors**
  - `opcode` -- Extract opcode mnemonics with full instruction data (mnemonic, instruction, size, bytes, section) -> JSONL output with `meta` and `opcodes` fields
  - `function_call` -- Extract function call graphs with `is_external` detection for all backends -> JSON output with `meta`, `call_graph` (nodes/functions), and `dot` fields
  - `binary_info` metadata extraction (arch, bits) embedded in opcode output
  - `is_external` detection for imported/external functions across all backends

- **CLI** (Click + rich-click)
  - `reverse-tool opcode -b <backend> -d <directory>` -- Opcode extraction
  - `reverse-tool function-call -b <backend> -d <directory>` -- Function call extraction
  - `reverse-tool doctor` -- Environment health check with version detection
  - `reverse-tool backends` -- List available backends and status
  - Auto-discovered extractor subcommands
  - `--verbose`, `--quiet`, `--version` global options
  - `config.toml` fallback for `--ghidra-path` and `--ida-path`

- **Docker**
  - Multi-stage, multi-target Dockerfile
  - `reverse-tool:latest` -- Ghidra + Radare2 (~1.08 GB)
  - `reverse-tool:ghidra` -- Ghidra only (~1.02 GB)
  - `reverse-tool:radare2` -- Radare2 only (~200 MB)
  - Non-root `reversetool` user
  - Smart entrypoint script

- **CI/CD**
  - GitHub Actions: lint -> test -> Docker build pipeline
  - Release workflow: GHCR Docker + GitHub Release
  - Weekly `pip-audit` dependency scanning
  - Dependabot for pip, GitHub Actions, and Docker

- **Open Source Infrastructure**
  - YAML issue templates (bug report, feature request, extractor proposal)
  - PR template with AI code disclosure
  - CONTRIBUTING.md with "Adding a New Extractor" tutorial
  - CODE_OF_CONDUCT.md (Contributor Covenant 2.1)
  - SECURITY.md with private vulnerability reporting
  - CODEOWNERS

[Unreleased]: https://github.com/bolin8017/ReverseTool/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/bolin8017/ReverseTool/releases/tag/v1.0.0
