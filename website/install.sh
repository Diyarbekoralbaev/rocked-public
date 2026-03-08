#!/bin/bash
set -e

REPO="Diyarbekoralbaev/rocked-public"
BINARY="rocked"

echo ""
echo "  Installing ${BINARY}..."
echo ""

# ── Detect OS ────────────────────────────────────
OS=$(uname -s)
case "$OS" in
    Linux*)  OS="linux" ;;
    Darwin*) OS="darwin" ;;
    MINGW*|MSYS*|CYGWIN*) OS="windows" ;;
    *) echo "Error: unsupported OS: $OS"; exit 1 ;;
esac

# ── Detect architecture ─────────────────────────
ARCH=$(uname -m)
case "$ARCH" in
    x86_64|amd64)  ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *) echo "Error: unsupported architecture: $ARCH"; exit 1 ;;
esac

# ── Build artifact name ─────────────────────────
NAME="${BINARY}-${OS}-${ARCH}"
if [ "$OS" = "windows" ]; then
    NAME="${NAME}.exe"
fi

# ── Resolve latest release tag ──────────────────
LATEST=$(curl -sI "https://github.com/${REPO}/releases/latest" \
    | grep -i "^location:" \
    | sed 's|.*/tag/||' \
    | tr -d '\r\n')

if [ -z "$LATEST" ]; then
    echo "Error: could not determine latest release"
    exit 1
fi

URL="https://github.com/${REPO}/releases/download/${LATEST}/${NAME}"

echo "  ${BINARY} ${LATEST} (${OS}/${ARCH})"
echo "  ${URL}"
echo ""

# ── Download ────────────────────────────────────
TMPFILE=$(mktemp)
HTTP_CODE=$(curl -sL -o "$TMPFILE" -w "%{http_code}" "$URL")

if [ "$HTTP_CODE" != "200" ]; then
    rm -f "$TMPFILE"
    echo "Error: download failed (HTTP ${HTTP_CODE})"
    echo "Check available releases: https://github.com/${REPO}/releases"
    exit 1
fi

chmod +x "$TMPFILE"

# ── Install ─────────────────────────────────────
INSTALL_DIR="/usr/local/bin"

if [ -w "$INSTALL_DIR" ]; then
    mv "$TMPFILE" "${INSTALL_DIR}/${BINARY}"
elif command -v sudo >/dev/null 2>&1; then
    sudo mv "$TMPFILE" "${INSTALL_DIR}/${BINARY}"
else
    INSTALL_DIR="${HOME}/.local/bin"
    mkdir -p "$INSTALL_DIR"
    mv "$TMPFILE" "${INSTALL_DIR}/${BINARY}"
    echo "  Installed to ${INSTALL_DIR}/${BINARY}"
    case ":$PATH:" in
        *":${INSTALL_DIR}:"*) ;;
        *) echo "  Add to PATH: export PATH=\"${INSTALL_DIR}:\$PATH\"" ;;
    esac
    echo ""
fi

echo "  Done! Run: ${BINARY} --help"
echo ""
