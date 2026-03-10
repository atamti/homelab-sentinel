#!/usr/bin/env bash
# deploy.sh — push homelab-sentinel to a live server
#
# Usage:
#   ./deploy.sh                    # deploy to localhost (run on the server itself)
#   ./deploy.sh user@host          # deploy to a remote server via SSH
#   ./deploy.sh --dry-run [target] # show what would happen without doing it
#
# Prerequisites on the target:
#   - Wazuh agent/manager installed at /var/ossec/
#   - systemd
#   - Python 3.10+ at /var/ossec/framework/python/bin/python3
#     (or system python3 — edit PYTHON_BIN below)

set -euo pipefail

# ── Configuration ────────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Scripts → deployment destinations
declare -A FILES=(
    ["telegram-commander.py"]="/var/ossec/integrations/telegram-commander.py"
    ["notify-ban.py"]="/var/ossec/active-response/bin/notify-ban.py"
    ["custom-telegram.py"]="/var/ossec/integrations/custom-telegram"
)

declare -A OWNERS=(
    ["telegram-commander.py"]="root:wazuh"
    ["notify-ban.py"]="root:wazuh"
    ["custom-telegram.py"]="root:wazuh"
)

declare -A PERMS=(
    ["telegram-commander.py"]="750"
    ["notify-ban.py"]="750"
    ["custom-telegram.py"]="750"
)

# Shared library
SENTINEL_PKG="sentinel"
SENTINEL_DEST="/var/ossec/integrations/sentinel"

SERVICE_FILE="homelab-sentinel.service"
SERVICE_DEST="/etc/systemd/system/${SERVICE_FILE}"
ENV_EXAMPLE=".env.example"
ENV_DEST="/etc/homelab-sentinel.env"
YAML_EXAMPLE="homelab-sentinel.yaml.example"
YAML_DEST="/etc/homelab-sentinel.yaml"

SERVICES_TO_RESTART=("homelab-sentinel")

# ── Parse arguments ──────────────────────────────────────────────────────────

DRY_RUN=false
TARGET=""

for arg in "$@"; do
    case "$arg" in
        --dry-run) DRY_RUN=true ;;
        *)         TARGET="$arg" ;;
    esac
done

# ── Helpers ──────────────────────────────────────────────────────────────────

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

info()  { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[✗]${NC} $*" >&2; }

run_cmd() {
    if [[ "$DRY_RUN" == true ]]; then
        echo "  (dry-run) $*"
        return 0
    fi

    if [[ -n "$TARGET" ]]; then
        ssh "$TARGET" "$@"
    else
        eval "$@"
    fi
}

copy_file() {
    local src="$1" dest="$2"
    if [[ "$DRY_RUN" == true ]]; then
        echo "  (dry-run) copy $src → $dest"
        return 0
    fi

    if [[ -n "$TARGET" ]]; then
        scp -q "$src" "${TARGET}:/tmp/_deploy_$(basename "$src")"
        ssh "$TARGET" "sudo mv /tmp/_deploy_$(basename "$src") $dest"
    else
        sudo cp "$src" "$dest"
    fi
}

copy_dir() {
    local src="$1" dest="$2"
    if [[ "$DRY_RUN" == true ]]; then
        echo "  (dry-run) copy dir $src → $dest"
        return 0
    fi

    if [[ -n "$TARGET" ]]; then
        scp -q -r "$src" "${TARGET}:/tmp/_deploy_sentinel"
        ssh "$TARGET" "sudo rm -rf $dest && sudo mv /tmp/_deploy_sentinel $dest"
    else
        sudo rm -rf "$dest"
        sudo cp -r "$src" "$dest"
    fi
}

# ── Pre-flight checks ───────────────────────────────────────────────────────

VERSION=$(grep -oP 'VERSION = "\K[^"]+' "${SCRIPT_DIR}/sentinel/config.py" 2>/dev/null || echo "unknown")
info "homelab-sentinel v${VERSION}"
info "Target: ${TARGET:-localhost}"
[[ "$DRY_RUN" == true ]] && warn "DRY RUN — no changes will be made"
echo ""

# Verify source files exist
for src in "${!FILES[@]}"; do
    if [[ ! -f "${SCRIPT_DIR}/${src}" ]]; then
        error "Missing source file: ${src}"
        exit 1
    fi
done

if [[ ! -d "${SCRIPT_DIR}/${SENTINEL_PKG}" ]]; then
    error "Missing sentinel/ package directory"
    exit 1
fi

# ── Deploy shared library ───────────────────────────────────────────────────

info "Deploying sentinel/ → ${SENTINEL_DEST}"
copy_dir "${SCRIPT_DIR}/${SENTINEL_PKG}" "${SENTINEL_DEST}"
run_cmd "sudo chown -R root:wazuh ${SENTINEL_DEST}"
run_cmd "sudo chmod -R 750 ${SENTINEL_DEST}"

# ── Deploy scripts ───────────────────────────────────────────────────────────

for src in "${!FILES[@]}"; do
    dest="${FILES[$src]}"
    owner="${OWNERS[$src]}"
    perm="${PERMS[$src]}"

    info "Deploying ${src} → ${dest}"
    copy_file "${SCRIPT_DIR}/${src}" "${dest}"
    run_cmd "sudo chown ${owner} ${dest}"
    run_cmd "sudo chmod ${perm} ${dest}"
done

# ── Deploy systemd service ──────────────────────────────────────────────────

info "Deploying ${SERVICE_FILE} → ${SERVICE_DEST}"
copy_file "${SCRIPT_DIR}/${SERVICE_FILE}" "${SERVICE_DEST}"
run_cmd "sudo chmod 644 ${SERVICE_DEST}"
run_cmd "sudo systemctl daemon-reload"

# ── Seed env file if missing ────────────────────────────────────────────────

info "Checking for ${ENV_DEST}"
env_exists=$(run_cmd "test -f ${ENV_DEST} && echo yes || echo no" 2>/dev/null || echo "no")

if [[ "$env_exists" != "yes" ]]; then
    warn "${ENV_DEST} not found — seeding from .env.example"
    warn "You MUST edit this file with real values before starting the service"
    copy_file "${SCRIPT_DIR}/${ENV_EXAMPLE}" "${ENV_DEST}"
    run_cmd "sudo chmod 600 ${ENV_DEST}"
else
    info "${ENV_DEST} already exists — not overwriting"
fi

# ── Seed YAML config if missing ─────────────────────────────────────────────

info "Checking for ${YAML_DEST}"
yaml_exists=$(run_cmd "test -f ${YAML_DEST} && echo yes || echo no" 2>/dev/null || echo "no")

if [[ "$yaml_exists" != "yes" ]]; then
    warn "${YAML_DEST} not found — seeding from ${YAML_EXAMPLE}"
    warn "Edit this file to enable output sanitization"
    copy_file "${SCRIPT_DIR}/${YAML_EXAMPLE}" "${YAML_DEST}"
    run_cmd "sudo chmod 600 ${YAML_DEST}"
else
    info "${YAML_DEST} already exists — not overwriting"
fi

# ── Drop latest example files + check for new keys ──────────────────────────

info "Updating example files alongside live configs"
copy_file "${SCRIPT_DIR}/${ENV_EXAMPLE}" "${ENV_DEST}.example"
run_cmd "sudo chmod 644 ${ENV_DEST}.example"
copy_file "${SCRIPT_DIR}/${YAML_EXAMPLE}" "${YAML_DEST}.example"
run_cmd "sudo chmod 644 ${YAML_DEST}.example"

# Compare env keys (variable names before '=')
if [[ "$DRY_RUN" != true && "$env_exists" == "yes" ]]; then
    new_env_keys=$(
        run_cmd "comm -23 \
            <(grep -oP '^[A-Z_]+(?==)' ${ENV_DEST}.example | sort) \
            <(grep -oP '^[A-Z_]+(?==)' ${ENV_DEST} | sort)" 2>/dev/null || true
    )
    if [[ -n "$new_env_keys" ]]; then
        warn "New env keys available in ${ENV_DEST}.example:"
        while IFS= read -r key; do
            warn "  $key"
        done <<< "$new_env_keys"
        warn "Review: diff ${ENV_DEST} ${ENV_DEST}.example"
    fi
fi

# Compare YAML top-level keys
if [[ "$DRY_RUN" != true && "$yaml_exists" == "yes" ]]; then
    new_yaml_keys=$(
        run_cmd "comm -23 \
            <(grep -oP '^[a-z_]+(?=:)' ${YAML_DEST}.example | sort) \
            <(grep -oP '^[a-z_]+(?=:)' ${YAML_DEST} | sort)" 2>/dev/null || true
    )
    if [[ -n "$new_yaml_keys" ]]; then
        warn "New YAML sections available in ${YAML_DEST}.example:"
        while IFS= read -r key; do
            warn "  $key"
        done <<< "$new_yaml_keys"
        warn "Review: diff ${YAML_DEST} ${YAML_DEST}.example"
    fi
fi

# ── Restart services ─────────────────────────────────────────────────────────

echo ""
for svc in "${SERVICES_TO_RESTART[@]}"; do
    info "Restarting ${svc}"
    run_cmd "sudo systemctl restart ${svc}"
    # Quick status check
    if [[ "$DRY_RUN" != true ]]; then
        sleep 1
        status=$(run_cmd "systemctl is-active ${svc}" 2>/dev/null || echo "unknown")
        if [[ "$status" == "active" ]]; then
            info "${svc}: ${status} ✓"
        else
            warn "${svc}: ${status} — check with: journalctl -u ${svc} -n 20"
        fi
    fi
done

echo ""
info "Deploy complete!"
