# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-04-01

### Added

- **Core Framework**
  - `BaseBackend` abstract class with Generic session typing and context manager
  - `BaseExtractor` abstract class with `__init_subclass__` auto-registration
  - `NullBackend` programmable testing backend
  - Parallel processing engine with `ProcessPoolExecutor` and `ProgressCallback`
  - Extractor auto-discovery via `pkgutil` scanning
  - TOML configuration loading (`~/.config/reverse-tool/config.toml`)
  - Structured exception hierarchy (`ReverseToolError`, `BackendError`, etc.)

- **Backends**
  - `GhidraBackend` — Ghidra 12.0.4 headless analyzer integration
  - `Radare2Backend` — Radare2 6.1.2 via r2pipe with pre-flight timeout check

- **Extractors**
  - `opcode` — Extract opcode mnemonics → CSV output (addr, opcode, section_name)
  - `function_call` — Extract function call graphs → DOT + JSON output

- **CLI** (Click + rich-click)
  - `reverse-tool opcode -b <backend> -d <directory>` — Opcode extraction
  - `reverse-tool function-call -b <backend> -d <directory>` — Function call extraction
  - `reverse-tool doctor` — Environment health check
  - `reverse-tool backends` — List available backends and status
  - Auto-discovered extractor subcommands
  - `--verbose`, `--quiet`, `--version` global options

- **Docker**
  - Multi-stage, multi-target Dockerfile
  - `reverse-tool:full` — Ghidra + Radare2 (~1.08GB)
  - `reverse-tool:ghidra-only` — Ghidra only (~1.02GB)
  - `reverse-tool:radare2-only` — Radare2 only (~200MB)
  - Non-root `reversetool` user
  - Smart entrypoint script

- **CI/CD**
  - GitHub Actions: lint → test → Docker build pipeline
  - Release workflow: PyPI (Trusted Publishing) + GHCR Docker + GitHub Release
  - Weekly `pip-audit` dependency scanning
  - Dependabot for pip, GitHub Actions, and Docker

- **Open Source Infrastructure**
  - YAML issue templates (bug report, feature request, extractor proposal)
  - PR template with AI code disclosure
  - CONTRIBUTING.md with "Adding a New Extractor" tutorial
  - CODE_OF_CONDUCT.md (Contributor Covenant 2.1)
  - SECURITY.md with private vulnerability reporting
  - CODEOWNERS
