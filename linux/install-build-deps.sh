#!/usr/bin/env bash

set -Eeuo pipefail

usage() {
    cat <<'EOF'
Usage: ./linux/install-build-deps.sh [OPTIONS]

Install build dependencies for Osza Browser on Ubuntu/Debian.

Options:
  --with-kde-integration  Install optional KDE integration dependencies.
  --with-python-plugins   Install optional Python plugin dependencies.
  --with-cups             Install optional CUPS development files.
  -h, --help              Show this help message.
EOF
}

with_kde=0
with_python=0
with_cups=0

while (($# > 0)); do
    case "$1" in
        --with-kde-integration)
            with_kde=1
            ;;
        --with-python-plugins)
            with_python=1
            ;;
        --with-cups)
            with_cups=1
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Error: Unknown option: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
    shift
done

if ! command -v apt-get >/dev/null 2>&1; then
    echo "Error: apt-get is required." >&2
    echo "This installer targets Ubuntu/Debian systems." >&2
    exit 1
fi

if [[ ! -r /etc/os-release ]]; then
    echo "Error: Cannot identify the Linux distribution." >&2
    exit 1
fi

# shellcheck disable=SC1091
source /etc/os-release

case " ${ID:-} ${ID_LIKE:-} " in
    *" ubuntu "*|*" debian "*)
        ;;
    *)
        echo "Error: Unsupported distribution: ${PRETTY_NAME:-unknown}" >&2
        echo "This installer targets Ubuntu/Debian systems." >&2
        exit 1
        ;;
esac

packages=(
    build-essential
    cmake
    extra-cmake-modules
    gettext
    pkg-config
    qt6-base-dev
    qt6-base-private-dev
    qt6-declarative-dev
    qt6-tools-dev
    qt6-tools-dev-tools
    qt6-webchannel-dev
    qt6-webengine-dev
    libkf6archive-dev
    libkf6i18n-dev
    libssl-dev
    libxcb1-dev
    libxcb-util-dev
)

if ((with_kde)); then
    packages+=(
        libkf6wallet-dev
        libkf6kio-dev
        libkf6crash-dev
        libkf6coreaddons-dev
        libkf6purpose-dev
        libkf6jobwidgets-dev
    )
fi

if ((with_python)); then
    packages+=(
        python3-dev
        libpyside6-dev
        libshiboken6-dev
        shiboken6
        python3-pyside6.qtcore
        python3-pyside6.qtgui
        python3-pyside6.qtwidgets
    )
fi

if ((with_cups)); then
    packages+=(libcups2-dev)
fi

if ((EUID == 0)); then
    APT=(apt-get)
else
    if ! command -v sudo >/dev/null 2>&1; then
        echo "Error: sudo is required. Run as root or install sudo." >&2
        exit 1
    fi
    APT=(sudo apt-get)
fi

echo "Updating package lists..."
"${APT[@]}" update

echo "Installing Osza Browser build dependencies..."
"${APT[@]}" install -y --no-install-recommends "${packages[@]}"

echo
echo "Build dependencies installed successfully."
echo
echo "Configure the project:"
echo "  cmake -S . -B build -DCMAKE_BUILD_TYPE=Release"
echo
echo "Build the project:"
echo '  cmake --build build --parallel'
