# Contributing to ReverseTool

Thanks for your interest in contributing! This guide helps you get started.

## Development Setup

### Prerequisites

- Python 3.12+
- [just](https://github.com/casey/just) (task runner)
- At least one backend: Ghidra 12.0.4 or Radare2 6.1.2

### Quick Setup

```bash
git clone https://github.com/bolin8017/ReverseTool.git
cd ReverseTool
python3.12 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Making Changes

### Branch Naming

- `feat/xxx` — New feature
- `fix/xxx` — Bug fix
- `docs/xxx` — Documentation
- `extractor/xxx` — New extractor

### Code Style

We use **ruff** for linting and formatting:

```bash
ruff check src/ tests/
ruff format src/ tests/
mypy src/reverse_tool/
```

### Testing

```bash
pytest tests/ -m unit -v              # Unit tests (no backends needed)
pytest tests/ -v --cov=reverse_tool   # With coverage
```

New features **must** include tests.

## Adding a New Extractor

This is the most common contribution. Here's the complete walkthrough:

### Step 1: Create the extractor directory

```
src/reverse_tool/extractors/my_feature/
├── __init__.py      # MyFeatureExtractor class
├── _ghidra.py       # Ghidra extraction logic
├── _radare2.py      # Radare2 extraction logic
└── _writer.py       # Output writer
```

### Step 2: Implement BaseExtractor

```python
# src/reverse_tool/extractors/my_feature/__init__.py
from reverse_tool.extractors import BaseExtractor, ExtractResult

class MyFeatureExtractor(BaseExtractor):
    @property
    def name(self) -> str:
        return "my_feature"

    @property
    def description(self) -> str:
        return "Extract my feature from binaries"

    @property
    def supported_backends(self) -> frozenset[str]:
        return frozenset({"ghidra", "radare2"})

    def extract(self, session, input_file, logger):
        # Your extraction logic here
        ...

    def write_output(self, result, output_dir):
        # Write results to disk
        ...
```

### Step 3: Add tests

```
tests/unit/test_my_feature.py
```

Test against `NullBackend` — no real backend needed for unit tests.

### Step 4: Submit PR

- Fill out the PR template
- Ensure CI passes
- Update CHANGELOG.md

## Commit Messages

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add string entropy extractor
fix: handle truncated PE headers
docs: add radare2 setup guide
test: add cross-backend consistency tests
chore: update dependencies
```

## AI-Assisted Code Policy

We welcome AI-assisted contributions. Requirements:
- Disclose in PR description (tool used, scope)
- You must understand and explain every line
- Same test and review standards apply
