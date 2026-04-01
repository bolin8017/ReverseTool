# ReverseTool development task runner

# Default: show available commands
default:
    @just --list

# Development setup
setup:
    uv venv --python 3.12 .venv
    . .venv/bin/activate && uv pip install -e ".[dev,radare2]"

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

# ============================================================
# Usage: Feature extraction workflows
# ============================================================

# Default data paths (override with: just extract-opcode INPUT=/other/path)
INPUT       := ""
OUTPUT      := ""
BACKEND     := "radare2"
TIMEOUT     := "600"
PATTERN     := ""
DOCKER_IMG  := "reverse-tool:full-test"

# Extract opcodes from binaries
extract-opcode INPUT OUTPUT BACKEND=BACKEND TIMEOUT=TIMEOUT:
    reverse-tool opcode -b {{BACKEND}} -d {{INPUT}} -o {{OUTPUT}} -t {{TIMEOUT}}

# Extract function calls from binaries
extract-funcall INPUT OUTPUT BACKEND=BACKEND TIMEOUT=TIMEOUT:
    reverse-tool function-call -b {{BACKEND}} -d {{INPUT}} -o {{OUTPUT}} -t {{TIMEOUT}}

# Extract ALL features (opcode + function_call) from one dataset
extract-all INPUT OUTPUT BACKEND=BACKEND TIMEOUT=TIMEOUT:
    reverse-tool opcode -b {{BACKEND}} -d {{INPUT}} -o {{OUTPUT}}/opcode -t {{TIMEOUT}}
    reverse-tool function-call -b {{BACKEND}} -d {{INPUT}} -o {{OUTPUT}}/function_call -t {{TIMEOUT}}

# Docker: extract opcodes
docker-extract-opcode INPUT OUTPUT BACKEND=BACKEND TIMEOUT=TIMEOUT:
    docker run --rm --user $(id -u):$(id -g) \
        -v {{INPUT}}:/data:ro \
        -v {{OUTPUT}}:/output \
        {{DOCKER_IMG}} opcode -b {{BACKEND}} -d /data -o /output -t {{TIMEOUT}}

# Docker: extract function calls
docker-extract-funcall INPUT OUTPUT BACKEND=BACKEND TIMEOUT=TIMEOUT:
    docker run --rm --user $(id -u):$(id -g) \
        -v {{INPUT}}:/data:ro \
        -v {{OUTPUT}}:/output \
        {{DOCKER_IMG}} function-call -b {{BACKEND}} -d /data -o /output -t {{TIMEOUT}}

# Docker: extract ALL features
docker-extract-all INPUT OUTPUT BACKEND=BACKEND TIMEOUT=TIMEOUT:
    docker run --rm --user $(id -u):$(id -g) \
        -v {{INPUT}}:/data:ro \
        -v {{OUTPUT}}/opcode:/output \
        {{DOCKER_IMG}} opcode -b {{BACKEND}} -d /data -o /output -t {{TIMEOUT}}
    docker run --rm --user $(id -u):$(id -g) \
        -v {{INPUT}}:/data:ro \
        -v {{OUTPUT}}/function_call:/output \
        {{DOCKER_IMG}} function-call -b {{BACKEND}} -d /data -o /output -t {{TIMEOUT}}

# ============================================================
# Development
# ============================================================

# Clean build artifacts
clean:
    rm -rf build/ dist/ *.egg-info src/*.egg-info .mypy_cache .pytest_cache .ruff_cache htmlcov/ .coverage
