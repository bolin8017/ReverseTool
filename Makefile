# ReverseTool Makefile
# Alternative to `just` for users without it installed.
# For the full task runner, install just: https://github.com/casey/just

.PHONY: setup lint fix typecheck test test-cov check clean docker-build

setup:
	python3.12 -m venv .venv
	.venv/bin/pip install -e ".[dev,radare2]"
	.venv/bin/pre-commit install

lint:
	.venv/bin/ruff check src/ tests/
	.venv/bin/ruff format --check src/ tests/

fix:
	.venv/bin/ruff check --fix src/ tests/
	.venv/bin/ruff format src/ tests/

typecheck:
	.venv/bin/mypy src/reverse_tool/

test:
	.venv/bin/python -m pytest tests/ -m unit -v

test-cov:
	.venv/bin/python -m pytest tests/ -m unit -v --cov=reverse_tool --cov-report=term-missing

check: lint typecheck test

clean:
	rm -rf .venv build dist *.egg-info .pytest_cache .mypy_cache .ruff_cache .coverage
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

docker-build:
	docker build --target full -t reverse-tool:latest -f docker/Dockerfile .

docker-build-r2:
	docker build --target radare2-only -t reverse-tool:radare2 -f docker/Dockerfile .

docker-build-ghidra:
	docker build --target ghidra-only -t reverse-tool:ghidra -f docker/Dockerfile .
