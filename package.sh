#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

MUSL_DIR="/opt/musl-cross"

MUSL_TARGETS=(
    "i686-linux-musl"
    "mips-linux-musl"
    "mipsel-linux-musl"
    "powerpc-linux-musl"
    "sh4-linux-musl"
    "arm-linux-musleabi"
    "x86_64-linux-musl"
    "aarch64-linux-musl"
    "m68k-linux-musl"
    "mips64-linux-musl"
    "mips64el-linux-musl"
    "s390x-linux-musl"
    "riscv64-linux-musl"
)

install_base_packages() {
    log_info "Installing base packages..."
    sudo apt update
    sudo apt upgrade -y
    sudo apt install -y \
        build-essential git wget bzip2 unzip make gcc g++ \
        mariadb-server python3 python3-pip jq \
        libgmp-dev libmpc-dev libmpfr-dev xz-utils autoconf automake libtool
}

install_musl_toolchains() {
    log_info "Installing musl cross-compilers to $MUSL_DIR..."
    
    sudo mkdir -p "$MUSL_DIR"
    
    for target in "${MUSL_TARGETS[@]}"; do
        local archive="${target}-cross.tgz"
        local url="https://musl.cc/${archive}"
        local install_path="${MUSL_DIR}/${target}-cross"
        
        if [ -d "$install_path" ]; then
            log_warn "$target already installed, skipping"
            continue
        fi
        
        log_info "Downloading $target..."
        if wget -q --show-progress -O "/tmp/${archive}" "$url"; then
            log_info "Extracting $target..."
            sudo tar -xzf "/tmp/${archive}" -C "$MUSL_DIR"
            rm -f "/tmp/${archive}"
            log_info "$target installed successfully"
        else
            log_error "Failed to download $target"
        fi
    done
    
    local path_line="export PATH=\"\$PATH"
    for target in "${MUSL_TARGETS[@]}"; do
        path_line+=":$MUSL_DIR/${target}-cross/bin"
    done
    path_line+="\""
    
    if grep -q "# musl cross-compilers" ~/.bashrc 2>/dev/null; then
        # Replace the existing path line
        sed -i '/# musl cross-compilers/!b;n;c'"$path_line" ~/.bashrc
        log_info "Updated musl toolchains PATH in ~/.bashrc"
    else
        echo "" >> ~/.bashrc
        echo "# musl cross-compilers" >> ~/.bashrc
        echo "$path_line" >> ~/.bashrc
        log_info "Added musl toolchains to PATH in ~/.bashrc"
    fi
    
    # Export it for the current session as well
    for target in "${MUSL_TARGETS[@]}"; do
        export PATH="$PATH:$MUSL_DIR/${target}-cross/bin"
    done
}

install_python_deps() {
    log_info "Installing Python dependencies..."
    pip install pycryptodome
}

install_go() {
    local GO_VERSION="1.26.1"
    
    if command -v go &> /dev/null; then
        log_warn "Go already installed: $(go version)"
        return
    fi
    
    log_info "Installing Go ${GO_VERSION}..."
    wget -q --show-progress "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz"
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf "go${GO_VERSION}.linux-amd64.tar.gz"
    rm "go${GO_VERSION}.linux-amd64.tar.gz"
    
    if ! grep -q "/usr/local/go/bin" ~/.bashrc; then
        echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
    fi
    
    log_info "Go ${GO_VERSION} installed"
}

verify_installation() {
    echo ""
    log_info "Verifying installation..."
    echo ""
    
    local all_ok=true
    
    for target in "${MUSL_TARGETS[@]}"; do
        local compiler="${target}-gcc"
        if command -v "$compiler" &> /dev/null; then
            echo -e "  ${GREEN}✓${NC} $compiler"
        else
            echo -e "  ${RED}✗${NC} $compiler not found"
            all_ok=false
        fi
    done
    
    echo ""
    if [ "$all_ok" = true ]; then
        log_info "All musl compilers installed successfully!"
    else
        log_warn "Some compilers not in PATH. Run 'source ~/.bashrc' to update PATH"
    fi
}

main() {
    install_base_packages
    install_musl_toolchains
    install_python_deps
    install_go
    verify_installation
    
    echo ""
    log_info "Installation complete!"
    log_warn "Please run 'source ~/.bashrc' or restart your shell to use musl compilers"
}

main