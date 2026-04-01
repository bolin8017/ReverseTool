#!/usr/bin/env bash
# ============================================================
# ReverseTool One-Click Installer
#
# Installs everything under $HOME — no system pollution.
# Only uses sudo for essential build dependencies (gcc, etc.)
# that cannot be installed in user space.
#
# Usage:
#   curl -sSf https://raw.githubusercontent.com/bolin8017/ReverseTool/main/install.sh | bash
#   # or
#   ./install.sh
#
# What gets installed (all under ~/.local or project .venv):
#   - uv          → Python version manager + package installer
#   - Python 3.12 → managed by uv (~/.local/share/uv/python/)
#   - Radare2     → compiled to ~/.local/ (bin, lib, share)
#   - ReverseTool → in project .venv/
#
# Optional (pass flags):
#   ./install.sh --with-ghidra    Install Ghidra 12.0.4 + JDK 21
#   ./install.sh --with-docker    Build Docker images (requires Docker)
#   ./install.sh --all            Install everything
# ============================================================

set -euo pipefail

# ── Configuration ───────────────────────────────────────────
PYTHON_VERSION="3.12"
RADARE2_VERSION="6.1.2"
GHIDRA_VERSION="12.0.4"
GHIDRA_DATE="20260303"
GHIDRA_SHA256="c3b458661d69e26e203d739c0c82d143cc8a4a29d9e571f099c2cf4bda62a120"
JDK_VERSION="21"

LOCAL_PREFIX="$HOME/.local"
LOCAL_BIN="$LOCAL_PREFIX/bin"

# ── Color output ────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

info()  { echo -e "${BLUE}[INFO]${NC} $*"; }
ok()    { echo -e "${GREEN}[OK]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
err()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }

# ── Shell rc file helper ─────────────────────────────────────
_get_rc_file() {
    if [[ -f "$HOME/.zshrc" ]] && [[ "$SHELL" == */zsh ]]; then
        echo "$HOME/.zshrc"
    else
        echo "$HOME/.bashrc"
    fi
}

# ── Parse flags ─────────────────────────────────────────────
WITH_GHIDRA=false
WITH_DOCKER=false

for arg in "$@"; do
    case "$arg" in
        --with-ghidra) WITH_GHIDRA=true ;;
        --with-docker) WITH_DOCKER=true ;;
        --all)         WITH_GHIDRA=true; WITH_DOCKER=true ;;
        --help|-h)
            echo "Usage: $0 [--with-ghidra] [--with-docker] [--all]"
            echo ""
            echo "  --with-ghidra  Install Ghidra 12.0.4 + JDK 21 (adds ~1GB)"
            echo "  --with-docker  Build Docker images"
            echo "  --all          Install everything"
            exit 0
            ;;
        *) err "Unknown flag: $arg"; exit 1 ;;
    esac
done

# ── Ensure PATH includes ~/.local/bin ───────────────────────
ensure_path() {
    if [[ ":$PATH:" != *":$LOCAL_BIN:"* ]]; then
        export PATH="$LOCAL_BIN:$PATH"
    fi

    # Persist in shell rc if not already there
    local rc_file
    rc_file="$(_get_rc_file)"

    if ! grep -q 'export PATH="$HOME/.local/bin:$PATH"' "$rc_file" 2>/dev/null; then
        echo '' >> "$rc_file"
        echo '# Added by ReverseTool installer' >> "$rc_file"
        echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$rc_file"
        info "Added ~/.local/bin to PATH in $rc_file"
    fi
}

# ── Step 1: System build dependencies (only sudo needed) ────
install_build_deps() {
    info "Checking build dependencies..."

    local missing=()
    command -v gcc      >/dev/null 2>&1 || missing+=(build-essential)
    command -v git      >/dev/null 2>&1 || missing+=(git)
    command -v curl     >/dev/null 2>&1 || missing+=(curl)
    command -v unzip    >/dev/null 2>&1 || missing+=(unzip)
    command -v pkg-config >/dev/null 2>&1 || missing+=(pkg-config)
    dpkg -l libzip-dev  >/dev/null 2>&1 || missing+=(libzip-dev)
    # meson/ninja will be installed via pip (user space)

    if [[ ${#missing[@]} -eq 0 ]]; then
        ok "All build dependencies present"
        return
    fi

    warn "Need to install system packages: ${missing[*]}"
    warn "This is the ONLY step that requires sudo."
    echo ""
    local answer
    if [[ ! -t 0 ]]; then
        warn "Non-interactive mode: will auto-install missing packages"
        answer="Y"
    else
        read -rp "  Install with 'sudo apt install ${missing[*]}'? [Y/n] " answer
    fi
    if [[ "${answer:-Y}" =~ ^[Yy]$ ]]; then
        sudo apt-get update -qq
        sudo apt-get install -y --no-install-recommends "${missing[@]}"
        ok "System dependencies installed"
    else
        err "Cannot continue without: ${missing[*]}"
        exit 1
    fi
}

# ── Step 2: Install uv (Python manager) ────────────────────
install_uv() {
    if command -v uv >/dev/null 2>&1; then
        ok "uv already installed ($(uv --version))"
        return
    fi

    info "Installing uv (Python version manager)..."
    curl -LsSf https://astral.sh/uv/install.sh | sh
    export PATH="$HOME/.local/bin:$PATH"  # uv installs here
    ok "uv installed ($(uv --version))"
}

# ── Step 3: Install Python 3.12 via uv ─────────────────────
install_python() {
    if uv python find "$PYTHON_VERSION" >/dev/null 2>&1; then
        ok "Python $PYTHON_VERSION already available ($(uv python find $PYTHON_VERSION))"
        return
    fi

    info "Installing Python $PYTHON_VERSION via uv (user space, no sudo)..."
    uv python install "$PYTHON_VERSION"
    ok "Python $PYTHON_VERSION installed"
}

# ── Step 4: Install Radare2 to ~/.local ─────────────────────
install_radare2() {
    if command -v r2 >/dev/null 2>&1; then
        local current_ver
        current_ver=$(r2 -v 2>/dev/null | head -1 | awk '{print $2}')
        ok "Radare2 already installed (version $current_ver)"
        return
    fi

    info "Building Radare2 $RADARE2_VERSION from source (installs to ~/.local)..."

    # Install meson + ninja via pip (user space)
    uv pip install --system meson ninja 2>/dev/null || pip install --user meson ninja

    local tmpdir
    tmpdir=$(mktemp -d)

    git clone --depth 1 --branch "$RADARE2_VERSION" \
        https://github.com/radareorg/radare2.git "$tmpdir/radare2"

    cd "$tmpdir/radare2"

    # Configure with user-local prefix
    meson setup build --prefix="$LOCAL_PREFIX" \
        --buildtype=release \
        -Ddefault_library=shared

    ninja -C build
    ninja -C build install

    cd - >/dev/null
    rm -rf "$tmpdir"

    # Ensure shared libs are found
    local ld_path="$LOCAL_PREFIX/lib/x86_64-linux-gnu:$LOCAL_PREFIX/lib"
    local rc_file
    rc_file="$(_get_rc_file)"
    if ! grep -q "ReverseTool radare2" "$rc_file" 2>/dev/null; then
        echo '' >> "$rc_file"
        echo "# ReverseTool radare2 shared libraries" >> "$rc_file"
        echo "export LD_LIBRARY_PATH=\"$ld_path:\$LD_LIBRARY_PATH\"" >> "$rc_file"
    fi
    export LD_LIBRARY_PATH="$ld_path:${LD_LIBRARY_PATH:-}"

    ok "Radare2 $RADARE2_VERSION installed to $LOCAL_PREFIX"
    r2 -v | head -1
}

# ── Step 5: Install Ghidra + JDK (optional) ─────────────────
install_ghidra() {
    local ghidra_dir="$LOCAL_PREFIX/share/ghidra"

    if [[ -d "$ghidra_dir" ]]; then
        ok "Ghidra already installed at $ghidra_dir"
        return
    fi

    info "Installing JDK $JDK_VERSION (Eclipse Temurin)..."
    local jdk_dir="$LOCAL_PREFIX/share/jdk-$JDK_VERSION"

    if [[ ! -d "$jdk_dir" ]]; then
        local arch
        arch=$(uname -m)
        [[ "$arch" == "x86_64" ]] && arch="x64"

        local jdk_url="https://api.adoptium.net/v3/binary/latest/$JDK_VERSION/ga/linux/$arch/jdk/hotspot/normal/eclipse"
        local jdk_tar
        jdk_tar=$(mktemp)

        info "Downloading JDK $JDK_VERSION..."
        curl -fSL -o "$jdk_tar" "$jdk_url"
        mkdir -p "$jdk_dir"
        tar xzf "$jdk_tar" --strip-components=1 -C "$jdk_dir"
        rm -f "$jdk_tar"
        ok "JDK $JDK_VERSION installed to $jdk_dir"
    fi

    export JAVA_HOME="$jdk_dir"
    export PATH="$JAVA_HOME/bin:$PATH"

    info "Downloading Ghidra $GHIDRA_VERSION..."
    local ghidra_zip
    ghidra_zip=$(mktemp)

    curl -fSL -o "$ghidra_zip" \
        "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_DATE}.zip"

    # Verify SHA256
    echo "$GHIDRA_SHA256  $ghidra_zip" | sha256sum -c - || {
        err "SHA256 verification failed!"
        rm -f "$ghidra_zip"
        exit 1
    }

    info "Extracting Ghidra..."
    local tmpdir
    tmpdir=$(mktemp -d)
    unzip -q "$ghidra_zip" -d "$tmpdir"
    mv "$tmpdir/ghidra_${GHIDRA_VERSION}_PUBLIC" "$ghidra_dir"
    rm -f "$ghidra_zip"
    rm -rf "$tmpdir"

    # Add to PATH
    local ghidra_env="
# ReverseTool Ghidra + JDK
export JAVA_HOME=\"$jdk_dir\"
export GHIDRA_INSTALL_DIR=\"$ghidra_dir\"
export PATH=\"\$JAVA_HOME/bin:\$GHIDRA_INSTALL_DIR/support:\$PATH\""

    local rc_file
    rc_file="$(_get_rc_file)"
    if ! grep -q "ReverseTool Ghidra" "$rc_file" 2>/dev/null; then
        echo "$ghidra_env" >> "$rc_file"
    fi

    ok "Ghidra $GHIDRA_VERSION installed to $ghidra_dir"
}

# ── Step 6: Install ReverseTool ─────────────────────────────
install_reversetool() {
    info "Setting up ReverseTool..."

    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

    # If running from the repo directory
    if [[ -f "$script_dir/pyproject.toml" ]]; then
        cd "$script_dir"
    fi

    if [[ ! -f "pyproject.toml" ]]; then
        info "Cloning ReverseTool repository..."
        git clone https://github.com/bolin8017/ReverseTool.git
        cd ReverseTool
    fi

    info "Creating virtual environment..."
    uv venv --python "$PYTHON_VERSION" .venv
    source .venv/bin/activate

    info "Installing ReverseTool + dependencies..."
    uv pip install -e ".[dev,radare2]"

    if $WITH_GHIDRA; then
        uv pip install pyghidra
    fi

    ok "ReverseTool installed in .venv"
}

# ── Step 7: Install just (task runner) ──────────────────────
install_just() {
    if command -v just >/dev/null 2>&1; then
        ok "just already installed"
        return
    fi

    info "Installing just (task runner)..."
    curl --proto '=https' --tlsv1.2 -sSf https://just.systems/install.sh \
        | bash -s -- --to "$LOCAL_BIN"
    ok "just installed"
}

# ── Step 8: Docker images (optional) ────────────────────────
build_docker() {
    if ! command -v docker >/dev/null 2>&1; then
        warn "Docker not found. Skipping Docker image build."
        return
    fi

    info "Building Docker images..."
    docker build --target radare2-only -t reverse-tool:radare2 -f docker/Dockerfile .
    docker build --target full -t reverse-tool:latest -f docker/Dockerfile .
    ok "Docker images built"
}

# ── Step 9: Verification ───────────────────────────────────
verify() {
    echo ""
    info "=== Verification ==="

    source .venv/bin/activate
    reverse-tool doctor

    echo ""
    ok "Installation complete!"
    echo ""
    echo "  To activate the environment:"
    echo "    source .venv/bin/activate"
    echo ""
    echo "  Quick start:"
    echo "    reverse-tool opcode -b radare2 -d /path/to/binaries -o ./output"
    echo "    reverse-tool function-call -b radare2 -d /path/to/binaries -o ./output"
    echo ""
    echo "  Or use just:"
    echo "    just extract-all /path/to/binaries ./output"
    echo ""
    if $WITH_GHIDRA; then
        rc_file="$(_get_rc_file)"
        echo "  Ghidra (restart shell or run: source $rc_file):"
        echo "    reverse-tool opcode -b ghidra -d /path/to/binaries -o ./output"
        echo ""
    fi
}

# ── Main ────────────────────────────────────────────────────
main() {
    echo ""
    echo "╔══════════════════════════════════════════════╗"
    echo "║     ReverseTool Installer v1.0.0            ║"
    echo "║     Binary Analysis Feature Extraction      ║"
    echo "╚══════════════════════════════════════════════╝"
    echo ""

    ensure_path
    install_build_deps
    install_uv
    install_python
    install_radare2
    if $WITH_GHIDRA; then
        install_ghidra
    fi
    install_reversetool
    install_just
    if $WITH_DOCKER; then
        build_docker
    fi
    verify
}

main
