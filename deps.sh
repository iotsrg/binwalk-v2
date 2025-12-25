#!/bin/bash

# Binwalk dependencies installer
# Updated for Ubuntu 24.04 LTS compatibility (Python 3.12)

set -eu
set -o nounset

set -eu
set -o nounset

# Define lsb_release fallback function first (needed for distro detection)
if ! which lsb_release > /dev/null 2>&1
then
    lsb_release() {
        if [ -f /etc/os-release ]
        then
            [[ "$1" = "-i" ]] && cat /etc/os-release | grep ^"ID=" | cut -d= -f 2 | tr -d '"'
            [[ "$1" = "-r" ]] && cat /etc/os-release | grep "VERSION_ID" | cut -d= -f 2 | tr -d '"'
        elif [ -f /etc/lsb-release ]
        then
            [[ "$1" = "-i" ]] && cat /etc/lsb-release | grep "DISTRIB_ID" | cut -d= -f 2
            [[ "$1" = "-r" ]] && cat /etc/lsb-release | grep "DISTRIB_RELEASE" | cut -d= -f 2
        else
            echo Unknown
        fi
    }
fi

distro="$(lsb_release -i 2>/dev/null | cut -f 2 || echo Unknown)"
distro_version="$(lsb_release -r 2>/dev/null | cut -f 2 | cut -c1-2 || echo 00)"

APTCMD="apt"
APTGETCMD="apt-get"

# Updated package list for Ubuntu 24.04 compatibility:
# - Removed python3-distutils (deprecated/removed in Python 3.12)
# - Removed python3-poetry (not needed, pipx handles its own venvs)
# - python3-setuptools provides distutils compatibility shim
# - Added: unrar, lz4, zstd, device-tree-compiler, unzip, xz-utils, curl
# - Added: 7zip (provides 7zz), dmg2img, unyaffs, cmake (for lzfse), clang (for dumpifs)
APT_CANDIDATES="7zip arj build-essential bzip2 cabextract clang cmake cpio cramfsswap curl device-tree-compiler dmg2img git gzip lhasa liblzma-dev liblzo2-dev liblz4-dev libucl-dev locales lz4 lzop mtd-utils p7zip p7zip-full python3-setuptools python3-matplotlib python3-capstone python3-pycryptodome python3-gnupg python3-pytest python3-pytest-cov pipx squashfs-tools sleuthkit srecord tar unyaffs unrar unzip wget xz-utils zlib1g-dev zstd"

# Initialize package manager variables with defaults
PKGCMD=""
PKGCMD_OPTS=""
PKG_CANDIDATES=""

# Check for root privileges
if [ $UID -eq 0 ]
then
    echo "UID is 0, sudo not required"
    SUDO=""
else
    SUDO="sudo -E"
fi

# ============================================
# Dependency Check Function
# ============================================
check_dependencies()
{
    # Temporarily disable exit on error for checks
    set +e
    
    local RED='\033[0;31m'
    local GREEN='\033[0;32m'
    local YELLOW='\033[1;33m'
    local NC='\033[0m'

    local PASS=0
    local FAIL=0
    local WARN=0

    echo ""
    echo "========================================"
    echo "  Binwalk Dependencies Checker"
    echo "========================================"
    echo ""

    echo "--- Core Extraction Tools ---"
    if command -v 7zz > /dev/null 2>&1 || command -v 7z > /dev/null 2>&1; then
        echo -e "[${GREEN}✓${NC}] 7zip - 7-Zip (archives, ISO, CPIO)"
        PASS=$((PASS + 1))
    else
        echo -e "[${RED}✗${NC}] 7zip - 7-Zip (archives, ISO, CPIO)"
        FAIL=$((FAIL + 1))
    fi

    for cmd_check in \
        "unzip:ZIP extraction" \
        "tar:TAR archive extraction" \
        "gzip:GZIP decompression" \
        "bzip2:BZIP2 decompression" \
        "xz:XZ/LZMA decompression" \
        "lzop:LZO decompression" \
        "lz4:LZ4 decompression" \
        "zstd:Zstandard decompression" \
        "cpio:CPIO archive extraction"
    do
        cmd="${cmd_check%%:*}"
        desc="${cmd_check#*:}"
        if command -v "$cmd" > /dev/null 2>&1; then
            echo -e "[${GREEN}✓${NC}] $cmd - $desc"
            PASS=$((PASS + 1))
        else
            echo -e "[${RED}✗${NC}] $cmd - $desc"
            FAIL=$((FAIL + 1))
        fi
    done

    echo ""
    echo "--- Filesystem Extraction ---"
    for cmd_check in \
        "sasquatch:SquashFS (non-standard)" \
        "unsquashfs:SquashFS (standard)" \
        "jefferson:JFFS2 filesystem" \
        "ubireader_extract_images:UBI image extraction" \
        "ubireader_extract_files:UBIFS extraction" \
        "yaffshiv:YAFFS filesystem" \
        "unyaffs:YAFFS2 filesystem" \
        "cramfsck:CramFS filesystem"
    do
        cmd="${cmd_check%%:*}"
        desc="${cmd_check#*:}"
        if command -v "$cmd" > /dev/null 2>&1; then
            echo -e "[${GREEN}✓${NC}] $cmd - $desc"
            PASS=$((PASS + 1))
        else
            echo -e "[${RED}✗${NC}] $cmd - $desc"
            FAIL=$((FAIL + 1))
        fi
    done

    echo ""
    echo "--- Firmware Tools ---"
    for cmd_check in \
        "uefi-firmware-parser:UEFI/BIOS firmware" \
        "vmlinux-to-elf:Linux kernel symbols" \
        "dumpifs:QNX IFS images" \
        "dmg2img:Apple DMG images" \
        "lzfse:Apple LZFSE compression"
    do
        cmd="${cmd_check%%:*}"
        desc="${cmd_check#*:}"
        if command -v "$cmd" > /dev/null 2>&1; then
            echo -e "[${GREEN}✓${NC}] $cmd - $desc"
            PASS=$((PASS + 1))
        else
            echo -e "[${RED}✗${NC}] $cmd - $desc"
            FAIL=$((FAIL + 1))
        fi
    done

    echo ""
    echo "--- Additional Extractors ---"
    for cmd_check in \
        "cabextract:Microsoft Cabinet" \
        "unrar:RAR archives" \
        "arj:ARJ archives" \
        "lha:LHA/LZH archives" \
        "srec_cat:Motorola S-record" \
        "tsk_recover:Filesystem recovery" \
        "dtc:Device Tree Compiler"
    do
        cmd="${cmd_check%%:*}"
        desc="${cmd_check#*:}"
        if command -v "$cmd" > /dev/null 2>&1; then
            echo -e "[${GREEN}✓${NC}] $cmd - $desc"
            PASS=$((PASS + 1))
        else
            echo -e "[${RED}✗${NC}] $cmd - $desc"
            FAIL=$((FAIL + 1))
        fi
    done

    echo ""
    echo "--- Build Tools ---"
    for cmd_check in \
        "gcc:GNU C Compiler" \
        "make:GNU Make" \
        "cmake:CMake" \
        "git:Git"
    do
        cmd="${cmd_check%%:*}"
        desc="${cmd_check#*:}"
        if command -v "$cmd" > /dev/null 2>&1; then
            echo -e "[${GREEN}✓${NC}] $cmd - $desc"
            PASS=$((PASS + 1))
        else
            echo -e "[${RED}✗${NC}] $cmd - $desc"
            FAIL=$((FAIL + 1))
        fi
    done

    echo ""
    echo "--- Python Modules ---"
    for mod_check in \
        "capstone:Disassembly framework" \
        "matplotlib:Entropy graphs" \
        "gnupg:GPG support"
    do
        mod="${mod_check%%:*}"
        desc="${mod_check#*:}"
        if python3 -c "import $mod" 2>/dev/null; then
            echo -e "[${GREEN}✓${NC}] python3-$mod - $desc"
            PASS=$((PASS + 1))
        else
            echo -e "[${RED}✗${NC}] python3-$mod - $desc"
            FAIL=$((FAIL + 1))
        fi
    done
    # PyCryptodome special check
    if python3 -c "import Cryptodome" 2>/dev/null || python3 -c "import Crypto" 2>/dev/null; then
        echo -e "[${GREEN}✓${NC}] python3-pycryptodome - Encryption"
        PASS=$((PASS + 1))
    else
        echo -e "[${RED}✗${NC}] python3-pycryptodome - Encryption"
        FAIL=$((FAIL + 1))
    fi

    echo ""
    echo "--- Libraries ---"
    for lib_check in \
        "liblzo2.so:LZO compression" \
        "liblz4.so:LZ4 compression" \
        "liblzfse.so:Apple LZFSE"
    do
        lib="${lib_check%%:*}"
        desc="${lib_check#*:}"
        if ldconfig -p 2>/dev/null | grep -q "$lib" || [ -f "/usr/lib/$lib" ] || [ -f "/usr/local/lib/$lib" ]; then
            echo -e "[${GREEN}✓${NC}] $lib - $desc"
            PASS=$((PASS + 1))
        else
            echo -e "[${RED}✗${NC}] $lib - $desc"
            FAIL=$((FAIL + 1))
        fi
    done

    echo ""
    echo "--- MTD/Flash Utilities ---"
    for cmd_check in \
        "nanddump:NAND flash dump" \
        "mkfs.jffs2:JFFS2 creation" \
        "ubinize:UBI image creation"
    do
        cmd="${cmd_check%%:*}"
        desc="${cmd_check#*:}"
        if command -v "$cmd" > /dev/null 2>&1; then
            echo -e "[${GREEN}✓${NC}] $cmd - $desc"
            PASS=$((PASS + 1))
        else
            echo -e "[${RED}✗${NC}] $cmd - $desc"
            FAIL=$((FAIL + 1))
        fi
    done

    echo ""
    echo "--- Optional ---"
    for cmd_check in \
        "binwalk:Binwalk itself" \
        "strings:String extraction" \
        "file:File type detection"
    do
        cmd="${cmd_check%%:*}"
        desc="${cmd_check#*:}"
        if command -v "$cmd" > /dev/null 2>&1; then
            echo -e "[${GREEN}✓${NC}] $cmd - $desc"
            PASS=$((PASS + 1))
        else
            echo -e "[${YELLOW}○${NC}] $cmd - $desc (optional)"
            WARN=$((WARN + 1))
        fi
    done

    echo ""
    echo "========================================"
    echo "  Summary"
    echo "========================================"
    echo -e "  ${GREEN}Passed:${NC}   $PASS"
    echo -e "  ${RED}Failed:${NC}   $FAIL"
    echo -e "  ${YELLOW}Optional:${NC} $WARN"
    echo "========================================"

    # Re-enable exit on error
    set -e

    if [ $FAIL -eq 0 ]; then
        echo -e "\n${GREEN}All required dependencies installed!${NC}\n"
        return 0
    else
        echo -e "\n${RED}Some dependencies are missing. Check errors above.${NC}\n"
        return 1
    fi
}

# Enable verbose mode for installation
set -x

install_yaffshiv()
{
    rm -rf yaffshiv 2>/dev/null || true
    git clone --quiet --depth 1 --branch "master" https://github.com/devttys0/yaffshiv
    (cd yaffshiv && pipx install .) || echo "WARNING: yaffshiv install had issues"
    rm -rf yaffshiv
}

# Fallback 2: devttys0 original + PR#56 (with CFLAGS workaround for modern GCC)
install_sasquatch()
{
    echo "Installing sasquatch from devttys0 original + PR#56..."
    rm -rf sasquatch 2>/dev/null || true
    git clone --quiet --depth 1 https://github.com/devttys0/sasquatch
    (cd sasquatch &&
        # Pull in PR #56 fixes for modern Ubuntu/GCC
        git fetch origin pull/56/head:pr56 2>/dev/null || true &&
        git checkout pr56 2>/dev/null || {
            # Fallback: apply CFLAGS fix for older sasquatch
            echo "PR #56 not available, applying CFLAGS workaround..."
            export CFLAGS="-fcommon -Wno-error"
        } &&
        ./build.sh) || echo "WARNING: sasquatch build had issues"
    rm -rf sasquatch
}

# Fallback 1: Use themactep's maintained fork (builds on modern GCC/Ubuntu 24.04)
install_sasquatch_alt()
{
    echo "Installing sasquatch from themactep fork..."
    rm -rf sasquatch 2>/dev/null || true
    git clone --quiet --depth 1 https://github.com/themactep/sasquatch.git
    (cd sasquatch && ./build.sh) || echo "WARNING: sasquatch_alt build had issues"
    rm -rf sasquatch
}

install_cramfstools()
{
    # Downloads cramfs tools from github and installs them to $INSTALL_LOCATION
    INSTALL_LOCATION=/usr/local/bin

    rm -rf cramfs-tools 2>/dev/null || true
    git clone --quiet --depth 1 --branch "master" https://github.com/npitre/cramfs-tools
    # There is no "make install"
    (cd cramfs-tools && make && $SUDO install cramfsck $INSTALL_LOCATION) || echo "WARNING: cramfstools build had issues"
    rm -rf cramfs-tools
}

install_pip_package()
{
    PACKAGE="$1"
    pipx install $PACKAGE
}

install_ubi_reader()
{
    # Install ubi_reader from onekey-sec fork (better maintained, Python 3.12 compatible)
    # Includes: ubireader_extract_files, ubireader_extract_images, ubireader_list_files, etc.
    pipx install git+https://github.com/onekey-sec/ubi_reader.git

    # Verify ubi_reader tools are accessible, create symlinks if needed
    if ! which ubireader_extract_files > /dev/null 2>&1; then
        echo "WARNING: ubireader_extract_files not in PATH, creating symlinks..."
        UBI_PATH=$(pipx environment --value PIPX_LOCAL_VENVS 2>/dev/null)/ubi-reader/bin
        if [ -d "$UBI_PATH" ]; then
            for tool in "$UBI_PATH"/ubireader_*; do
                [ -f "$tool" ] && $SUDO ln -sf "$tool" /usr/local/bin/
            done
        else
            # Fallback: try pip install with --break-system-packages (Ubuntu 24.04+)
            echo "Trying pip fallback installation for ubi_reader..."
            pip3 install git+https://github.com/onekey-sec/ubi_reader.git --break-system-packages 2>/dev/null || \
            python3 -m pip install git+https://github.com/onekey-sec/ubi_reader.git --user
        fi
    fi
}

install_jefferson()
{
    pipx install jefferson

    # Verify jefferson is accessible
    if ! which jefferson > /dev/null 2>&1; then
        echo "WARNING: jefferson not in PATH, creating symlinks..."
        JEFF_PATH=$(pipx environment --value PIPX_LOCAL_VENVS 2>/dev/null)/jefferson/bin
        if [ -f "$JEFF_PATH/jefferson" ]; then
            $SUDO ln -sf "$JEFF_PATH/jefferson" /usr/local/bin/
        fi
    fi
}

install_uefi_firmware()
{
    # UEFI firmware extraction support
    # Binary name is: uefi-firmware-parser
    pipx install uefi_firmware

    if ! which uefi-firmware-parser > /dev/null 2>&1; then
        echo "WARNING: uefi-firmware-parser not in PATH, creating symlinks..."
        UEFI_PATH=$(pipx environment --value PIPX_LOCAL_VENVS 2>/dev/null)/uefi-firmware/bin
        if [ -f "$UEFI_PATH/uefi-firmware-parser" ]; then
            $SUDO ln -sf "$UEFI_PATH/uefi-firmware-parser" /usr/local/bin/
        else
            pip3 install uefi_firmware --break-system-packages 2>/dev/null || \
            python3 -m pip install uefi_firmware --user
        fi
    fi
}

install_dumpifs()
{
    # QNX IFS image extraction
    # Using ttepatti/dumpifs-linux fork which has fixes for modern compilers
    rm -rf dumpifs-linux 2>/dev/null || true
    git clone --quiet --depth 1 https://github.com/ttepatti/dumpifs-linux.git
    cd dumpifs-linux
    
    # Remove pre-compiled binary and rebuild for this system
    rm -f dumpifs 2>/dev/null || true
    
    if make; then
        $SUDO cp ./dumpifs /usr/local/bin/dumpifs
        echo "Installed dumpifs"
        # Also install helper scripts if present
        [ -f ./dumpifs-folderized.sh ] && $SUDO cp ./dumpifs-folderized.sh /usr/local/bin/
    else
        echo "WARNING: dumpifs compilation failed"
    fi
    
    cd ..
    rm -rf dumpifs-linux
}

install_vmlinux_to_elf()
{
    # Linux kernel extraction tool
    # Not on PyPI - must install from GitHub
    pipx install git+https://github.com/marin-m/vmlinux-to-elf.git
    
    if ! which vmlinux-to-elf > /dev/null 2>&1; then
        echo "WARNING: vmlinux-to-elf not in PATH, creating symlinks..."
        VMLINUX_PATH=$(pipx environment --value PIPX_LOCAL_VENVS 2>/dev/null)/vmlinux-to-elf/bin
        if [ -f "$VMLINUX_PATH/vmlinux-to-elf" ]; then
            $SUDO ln -sf "$VMLINUX_PATH/vmlinux-to-elf" /usr/local/bin/
        else
            pip3 install git+https://github.com/marin-m/vmlinux-to-elf.git --break-system-packages 2>/dev/null || \
            python3 -m pip install git+https://github.com/marin-m/vmlinux-to-elf.git --user
        fi
    fi
}

install_lzfse()
{
    # Apple LZFSE compression (used in iOS/macOS firmware)
    rm -rf lzfse 2>/dev/null || true
    git clone --quiet --depth 1 https://github.com/lzfse/lzfse.git
    (cd lzfse && mkdir -p build && cd build && cmake .. && make && $SUDO make install) || echo "WARNING: lzfse build had issues"
    rm -rf lzfse
}

install_sasquatch_deb()
{
    # Install sasquatch from onekey-sec prebuilt deb (easiest for Ubuntu 24.04)
    # https://github.com/onekey-sec/sasquatch/releases
    ARCH=$(dpkg --print-architecture)
    SASQUATCH_VERSION="sasquatch-v4.5.1-5"
    
    echo "Downloading sasquatch from onekey-sec..."
    curl -L -o sasquatch_1.0.deb "https://github.com/onekey-sec/sasquatch/releases/download/${SASQUATCH_VERSION}/sasquatch_1.0_${ARCH}.deb" 2>/dev/null
    
    if [ -f sasquatch_1.0.deb ] && [ -s sasquatch_1.0.deb ]; then
        $SUDO dpkg -i sasquatch_1.0.deb
        rm -f sasquatch_1.0.deb
        echo "sasquatch installed successfully from onekey-sec deb"
        return 0
    fi
    
    echo "Failed to download sasquatch deb"
    rm -f sasquatch_1.0.deb 2>/dev/null
    return 1
}

find_path()
{
    FILE_NAME="$1"

    echo -ne "checking for $FILE_NAME..."
    if which $FILE_NAME > /dev/null 2>&1
    then
        echo "yes"
        return 0
    else
        echo "no"
        return 1
    fi
}

# Show distro info
echo ""
echo "=== Binwalk Dependencies Installer ==="
echo ""
if [ "$distro" != "Unknown" ]
then
    echo "Detected: $distro $distro_version"
else
    echo "WARNING: Distro not detected, using package-manager defaults"
fi
echo ""

# Check for supported package managers and set the PKG_* envars appropriately
if find_path $APTCMD
then
    if "$APTCMD" install -s -y dpkg > /dev/null 2>&1
    then
        PKGCMD="$APTCMD"
        PKGCMD_OPTS="install -y"
        PKG_CANDIDATES="$APT_CANDIDATES"
    else
        PKGCMD="$APTGETCMD"
        PKGCMD_OPTS="install -y"
        PKG_CANDIDATES="$APT_CANDIDATES"
    fi
elif find_path $APTGETCMD
then
    PKGCMD="$APTGETCMD"
    PKGCMD_OPTS="install -y"
    PKG_CANDIDATES="$APT_CANDIDATES"
else
    echo "ERROR: No supported package manager found (apt or apt-get required)"
    exit 1
fi

# Install system packages
if ! $SUDO $PKGCMD $PKGCMD_OPTS $PKG_CANDIDATES
then
    echo "Package installation failed: $PKG_CANDIDATES"
    exit 1
fi

# Ensure pipx path is set up and add to current session
pipx ensurepath 2>/dev/null || true
export PATH="$HOME/.local/bin:$PATH"

# Do the install(s)
cd /tmp

install_ubi_reader
install_jefferson
install_uefi_firmware

# Sasquatch installation with fallback chain:
# 1. onekey-sec prebuilt .deb (easiest for Ubuntu 24.04)
# 2. themactep fork (maintained, builds on modern GCC)
# 3. devttys0 original + PR#56 (with CFLAGS workaround)
if ! install_sasquatch_deb; then
    echo "Prebuilt sasquatch deb not available, trying themactep fork..."
    if ! install_sasquatch_alt; then
        echo "themactep fork failed, trying devttys0 original + PR#56..."
        install_sasquatch
    fi
fi

install_yaffshiv
install_cramfstools
install_vmlinux_to_elf
install_lzfse
install_dumpifs

echo ""
echo "=== Installation complete ==="
echo "You may need to restart your shell or run: source ~/.bashrc"
echo "to use pipx-installed tools (jefferson, ubi_reader, yaffshiv)"
echo ""
echo "Running dependency check..."
echo ""

# Run dependency check after installation
check_dependencies
