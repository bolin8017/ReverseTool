# ReverseTool development task runner

# Default: show available commands
default:
    @just --list

# Development setup
setup:
    python3.12 -m venv .venv
    . .venv/bin/activate && pip install -e ".[dev]"

# Linting
lint:
    ruff check src/ tests/
    ruff format --check src/ tests/

# Auto-fix lint issues
fix:
    ruff check --fix src/ tests/
    ruff format src/ tests/

# Type checking
typecheck:
    mypy src/reverse_tool/

# Run unit tests
test:
    pytest tests/ -m unit -v

# Run tests with coverage
test-cov:
    pytest tests/ -v --cov=reverse_tool --cov-report=term-missing --cov-report=html

# Run all quality checks
check: lint typecheck test

# Docker: build all images
docker-build:
    docker build --target full -t reverse-tool:latest -f docker/Dockerfile .
    docker build --target ghidra-only -t reverse-tool:ghidra -f docker/Dockerfile .
    docker build --target radare2-only -t reverse-tool:radare2 -f docker/Dockerfile .

# Docker: build radare2-only (fastest)
docker-build-r2:
    docker build --target radare2-only -t reverse-tool:radare2 -f docker/Dockerfile .

# Docker: run doctor inside container
docker-doctor:
    docker run --rm reverse-tool:latest doctor

# Clean build artifacts
clean:
    rm -rf build/ dist/ *.egg-info .mypy_cache .pytest_cache .ruff_cache htmlcov/ .coverage
