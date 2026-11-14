#!/bin/bash
#
# Build BearSSL static library for all musl cross-compile architectures.
# Output: tools/bearssl-build/<arch>/lib/libbearssl.a + headers
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BEARSSL_VERSION="0.6"
BEARSSL_URL="https://www.bearssl.org/bearssl-${BEARSSL_VERSION}.tar.gz"
SRC_DIR="$SCRIPT_DIR/bearssl-src"
BUILD_BASE="$SCRIPT_DIR/bearssl-build"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

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

get_compiler() {
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
        aarch64)        echo "aarch64-linux-musl-gcc" ;;
        x86_64)         echo "x86_64-linux-musl-gcc" ;;
        *)              echo "" ;;
    esac
}

# Download BearSSL source if not present
download_bearssl() {
    if [ -d "$SRC_DIR" ] && [ -f "$SRC_DIR/inc/bearssl.h" ]; then
        echo -e "${BLUE}[INFO]${NC} BearSSL source already present"
        return 0
    fi

    echo -e "${BLUE}[INFO]${NC} Downloading BearSSL ${BEARSSL_VERSION}..."
    mkdir -p "$SRC_DIR"

    local tarball="/tmp/bearssl-${BEARSSL_VERSION}.tar.gz"
    if [ ! -f "$tarball" ]; then
        wget -q -O "$tarball" "$BEARSSL_URL" || curl -sL -o "$tarball" "$BEARSSL_URL"
    fi

    tar xzf "$tarball" -C "$SRC_DIR" --strip-components=1
    echo -e "${GREEN}[OK]${NC} BearSSL source extracted to $SRC_DIR"
}

# Build for a single architecture
build_arch() {
    local arch="$1"
    local cc=$(get_compiler "$arch")

    if [ -z "$cc" ]; then
        echo -e "${RED}[ERROR]${NC} Unknown arch: $arch"
        return 1
    fi

    if ! command -v "$cc" &>/dev/null; then
        echo -e "${YELLOW}[WARN]${NC} Compiler not found: $cc (skipping $arch)"
        return 1
    fi

    local out_dir="$BUILD_BASE/$arch"
    local lib_dir="$out_dir/lib"
    local inc_dir="$out_dir/inc"

    # Skip if already built
    if [ -f "$lib_dir/libbearssl.a" ]; then
        echo -e "${GREEN}[OK]${NC} $arch (cached)"
        return 0
    fi

    echo -ne "${BLUE}[BUILD]${NC} $arch ... "

    mkdir -p "$lib_dir" "$inc_dir"

    # Copy headers
    cp -r "$SRC_DIR/inc/"* "$inc_dir/"

    # Collect all BearSSL .c source files
    local src_files=""
    for f in "$SRC_DIR/src/"*.c "$SRC_DIR/src/"*/*.c; do
        [ -f "$f" ] && src_files="$src_files $f"
    done

    # Compile all objects
    local obj_dir="/tmp/bearssl_obj_${arch}"
    rm -rf "$obj_dir"
    mkdir -p "$obj_dir"

    local cflags="-Os -fomit-frame-pointer -fvisibility=hidden -fno-ident -I${SRC_DIR}/inc -I${SRC_DIR}/src -DBR_USE_UNIX_TIME=1"

    # Architecture-specific flags
    case "$arch" in
        i486)    cflags="$cflags -march=i486" ;;
        i586)    cflags="$cflags -march=i586" ;;
        i686)    cflags="$cflags -march=i686" ;;
        armv4l)  cflags="$cflags -march=armv4 -mabi=aapcs-linux" ;;
        armv5l)  cflags="$cflags -march=armv5t -mabi=aapcs-linux" ;;
        armv6l)  cflags="$cflags -march=armv6 -mabi=aapcs-linux -mfloat-abi=softfp" ;;
        armv7l)  cflags="$cflags -march=armv7-a -mabi=aapcs-linux -mfloat-abi=softfp" ;;
        aarch64) cflags="$cflags -march=armv8-a" ;;
    esac

    local failed=0
    for src in $src_files; do
        local obj_name=$(basename "$src" .c).o
        # Handle duplicate basenames from subdirectories
        local subdir=$(basename $(dirname "$src"))
        if [ "$subdir" != "src" ]; then
            obj_name="${subdir}_${obj_name}"
        fi
        $cc $cflags -c "$src" -o "$obj_dir/$obj_name" 2>/dev/null || { failed=1; break; }
    done

    if [ $failed -ne 0 ]; then
        echo -e "${RED}FAILED${NC}"
        rm -rf "$obj_dir"
        return 1
    fi

    # Create static library
    local ar_tool="${cc%-gcc}-ar"
    if ! command -v "$ar_tool" &>/dev/null; then
        ar_tool="ar"
    fi

    $ar_tool rcs "$lib_dir/libbearssl.a" "$obj_dir"/*.o 2>/dev/null

    rm -rf "$obj_dir"

    local size=$(ls -lh "$lib_dir/libbearssl.a" | awk '{print $5}')
    echo -e "${GREEN}OK${NC} ($size)"
    return 0
}

# Main
main() {
    echo -e "${BLUE}=== BearSSL Cross-Compile Build ===${NC}"
    echo ""

    download_bearssl

    echo ""
    echo -e "${BLUE}[INFO]${NC} Building for ${#ARCHS[@]} architectures..."
    echo ""

    local success=0
    local failed=0

    for arch in "${ARCHS[@]}"; do
        if build_arch "$arch"; then
            success=$((success + 1))
        else
            failed=$((failed + 1))
        fi
    done

    echo ""
    echo -e "${GREEN}[DONE]${NC} Success: $success, Failed: $failed"
    echo -e "${BLUE}[INFO]${NC} Libraries in: $BUILD_BASE/<arch>/lib/libbearssl.a"
}

main "$@"
