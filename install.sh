#!/bin/bash
set -e

# Midsummer Vault — install CLI + Claude Code plugin
# Usage: curl -fsSL https://raw.githubusercontent.com/midsummer-new/vault/main/install.sh | sh

REPO="midsummer-new/vault"
PLUGIN_REPO="midsummer-new/vault-server"

C='\033[0;36m'
G='\033[0;32m'
Y='\033[0;33m'
R='\033[0;31m'
N='\033[0m'
B='\033[1m'

info()  { echo -e "${C}$1${N}"; }
ok()    { echo -e "${G}✓ $1${N}"; }
warn()  { echo -e "${Y}! $1${N}"; }
fail()  { echo -e "${R}✗ $1${N}"; exit 1; }

echo ""
echo -e "${B}Midsummer Vault${N} — Secret management for AI agents"
echo ""

# ─── Detect platform ─────────────────────────────────────────────────────────

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "$ARCH" in
  x86_64)  ARCH="amd64" ;;
  aarch64) ARCH="arm64" ;;
  arm64)   ARCH="arm64" ;;
  *)       fail "Unsupported architecture: $ARCH" ;;
esac

case "$OS" in
  linux)  ;;
  darwin) ;;
  *)      fail "Unsupported OS: $OS. Use 'go install' instead." ;;
esac

info "Platform: ${OS}/${ARCH}"

# ─── Install CLI ─────────────────────────────────────────────────────────────

INSTALL_DIR="${VAULT_INSTALL_DIR:-/usr/local/bin}"
BINARY="vault"

# check if already installed
if command -v vault &>/dev/null; then
  CURRENT_VERSION=$(vault --version 2>/dev/null || echo "unknown")
  warn "vault already installed (${CURRENT_VERSION}). Upgrading..."
fi

# try to get latest release from GitHub
info "Downloading vault CLI..."

if command -v gh &>/dev/null; then
  # use gh CLI if available
  DOWNLOAD_URL=$(gh release view --repo "$REPO" --json assets --jq ".assets[] | select(.name | test(\"${OS}_${ARCH}\")) | .url" 2>/dev/null || echo "")
fi

if [ -z "$DOWNLOAD_URL" ]; then
  # fallback: get latest tag and construct URL
  LATEST_TAG=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"//;s/".*//' || echo "")

  if [ -z "$LATEST_TAG" ]; then
    # no releases yet — try building from source
    warn "No releases found. Attempting to build from source..."

    if command -v go &>/dev/null; then
      go install "github.com/${REPO}/cmd/vault@latest" 2>/dev/null && ok "Installed via go install" || true
    fi

    if ! command -v vault &>/dev/null; then
      # try npm
      if command -v npm &>/dev/null; then
        info "Trying npm install..."
        npm install -g @midsummerai/vault 2>/dev/null && ok "Installed via npm" || true
      fi
    fi

    if ! command -v vault &>/dev/null; then
      fail "Could not install vault CLI. Install Go and run: go install github.com/${REPO}/cmd/vault@latest"
    fi
  else
    TARBALL="vault-server_${LATEST_TAG#v}_${OS}_${ARCH}.tar.gz"
    DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${LATEST_TAG}/${TARBALL}"

    TMP_DIR=$(mktemp -d)
    trap "rm -rf $TMP_DIR" EXIT

    curl -fsSL "$DOWNLOAD_URL" -o "${TMP_DIR}/vault.tar.gz" || fail "Download failed: $DOWNLOAD_URL"
    tar -xzf "${TMP_DIR}/vault.tar.gz" -C "$TMP_DIR" || fail "Extract failed"

    # install binary
    if [ -w "$INSTALL_DIR" ]; then
      cp "${TMP_DIR}/vault" "${INSTALL_DIR}/${BINARY}"
      chmod +x "${INSTALL_DIR}/${BINARY}"
    else
      info "Need sudo to install to ${INSTALL_DIR}"
      sudo cp "${TMP_DIR}/vault" "${INSTALL_DIR}/${BINARY}"
      sudo chmod +x "${INSTALL_DIR}/${BINARY}"
    fi

    ok "Installed vault CLI to ${INSTALL_DIR}/${BINARY}"
  fi
else
  ok "vault CLI already installed"
fi

# verify
if command -v vault &>/dev/null; then
  VERSION=$(vault --version 2>/dev/null || echo "installed")
  ok "vault CLI ready (${VERSION})"
else
  warn "vault binary installed but not on PATH. Add ${INSTALL_DIR} to your PATH."
fi

# ─── Install Claude Code plugin ─────────────────────────────────────────────

info ""
info "Installing Claude Code plugin..."

# check if claude is available
if command -v claude &>/dev/null; then
  # try plugin install
  claude plugin install "${PLUGIN_REPO}" 2>/dev/null && ok "Claude Code plugin installed" || {
    warn "Plugin install via CLI failed. Trying manual install..."
    PLUGIN_MANUAL=true
  }
else
  warn "Claude Code CLI not found. Skipping plugin install."
  warn "Install manually: claude plugin install ${PLUGIN_REPO}"
  PLUGIN_MANUAL=true
fi

# manual plugin install fallback
if [ "$PLUGIN_MANUAL" = true ] && command -v git &>/dev/null; then
  PLUGIN_DIR="${HOME}/.claude/plugins/midsummer-vault"
  if [ -d "$PLUGIN_DIR" ]; then
    warn "Plugin directory already exists at ${PLUGIN_DIR}"
  else
    mkdir -p "$(dirname "$PLUGIN_DIR")"
    # clone just the plugin subdirectory
    TMP_CLONE=$(mktemp -d)
    git clone --depth 1 --filter=blob:none --sparse "https://github.com/${PLUGIN_REPO}.git" "$TMP_CLONE" 2>/dev/null
    cd "$TMP_CLONE" && git sparse-checkout set claude-code-plugin 2>/dev/null
    if [ -d "${TMP_CLONE}/claude-code-plugin" ]; then
      cp -r "${TMP_CLONE}/claude-code-plugin" "$PLUGIN_DIR"
      ok "Claude Code plugin installed to ${PLUGIN_DIR}"
    else
      warn "Could not extract plugin. Install manually after repo is published."
    fi
    rm -rf "$TMP_CLONE"
  fi
fi

# ─── Done ────────────────────────────────────────────────────────────────────

echo ""
echo -e "${B}Setup complete!${N}"
echo ""
echo "  Quick start:"
echo "    cd your-project"
echo "    vault init                         # create encrypted vault"
echo "    vault set STRIPE_KEY sk_live_...   # store a secret"
echo "    vault run -- npm run dev           # run with secrets injected"
echo ""
echo "  Import existing .env:"
echo "    vault import .env.local"
echo ""
echo "  The AI agent never sees your secret values."
echo ""
