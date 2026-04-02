#!/usr/bin/env bash
# deploy.sh — push homelab-sentinel to a live server
#
# Usage:
#   ./deploy.sh                    # deploy to localhost (run on the server itself)
#   ./deploy.sh user@host          # deploy to a remote server via SSH
#   ./deploy.sh --dry-run [target] # show what would happen without doing it
#   ./deploy.sh --force            # overwrite config files without prompting
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
FORCE=false
TARGET=""

for arg in "$@"; do
    case "$arg" in
        --dry-run) DRY_RUN=true ;;
        --force)   FORCE=true ;;
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

# deploy_config_file — interactive dpkg-style config file handler
#
# When the destination file already exists and differs from the source,
# prompts the user to:
#   [o] Overwrite — replace with the new version
#   [k] Keep     — leave the existing file untouched (default)
#   [d] Diff     — show a unified diff, then re-prompt
#   [s] Shell    — drop to a shell for manual merging, then re-prompt
#
# Usage: deploy_config_file <source> <dest> <owner> <perm> <label>
deploy_config_file() {
    local src="$1" dest="$2" owner="$3" perm="$4" label="$5"

    info "Checking for ${dest}"
    local exists
    exists=$(run_cmd "test -f ${dest} && echo yes || echo no" 2>/dev/null || echo "no")

    if [[ "$exists" != "yes" ]]; then
        warn "${dest} not found — seeding from ${label}"
        copy_file "${src}" "${dest}"
        run_cmd "sudo chown ${owner} ${dest}"
        run_cmd "sudo chmod ${perm} ${dest}"
        return
    fi

    # File exists — check for differences
    if [[ "$DRY_RUN" == true ]]; then
        info "${dest} exists — would prompt for action"
        return
    fi

    # Fetch remote file to a temp location for comparison
    local tmp_live
    tmp_live=$(mktemp)
    if [[ -n "$TARGET" ]]; then
        ssh "$TARGET" "sudo cat ${dest}" > "$tmp_live" 2>/dev/null
    else
        sudo cat "${dest}" > "$tmp_live" 2>/dev/null
    fi

    if diff -q "$src" "$tmp_live" &>/dev/null; then
        info "${dest} is unchanged"
        rm -f "$tmp_live"
        run_cmd "sudo chown ${owner} ${dest}"
        run_cmd "sudo chmod ${perm} ${dest}"
        return
    fi

    # Files differ — prompt (or force)
    if [[ "$FORCE" == true ]]; then
        warn "${dest} differs — overwriting (--force)"
        copy_file "$src" "$dest"
        run_cmd "sudo chown ${owner} ${dest}"
        run_cmd "sudo chmod ${perm} ${dest}"
        rm -f "$tmp_live"
        return
    fi

    warn "Config file ${dest} has changed."
    while true; do
        echo -e "  ${YELLOW}[o]${NC} Overwrite with new version"
        echo -e "  ${YELLOW}[k]${NC} Keep existing (default)"
        echo -e "  ${YELLOW}[d]${NC} Show diff"
        echo -e "  ${YELLOW}[s]${NC} Drop to shell"
        read -rp "  Choice [o/k/d/s]: " choice
        case "${choice:-k}" in
            o|O)
                copy_file "$src" "$dest"
                run_cmd "sudo chown ${owner} ${dest}"
                run_cmd "sudo chmod ${perm} ${dest}"
                info "${dest} overwritten"
                break
                ;;
            k|K)
                info "Keeping existing ${dest}"
                run_cmd "sudo chown ${owner} ${dest}"
                run_cmd "sudo chmod ${perm} ${dest}"
                break
                ;;
            d|D)
                echo ""
                diff -u --color=always --label "installed: ${dest}" --label "new: ${label}" \
                    "$tmp_live" "$src" || true
                echo ""
                ;;
            s|S)
                warn "Dropping to shell. The files are:"
                warn "  Installed: ${dest}"
                warn "  New:       ${src}"
                warn "Type 'exit' when done."
                if [[ -n "$TARGET" ]]; then
                    ssh -t "$TARGET" "sudo -i"
                else
                    bash
                fi
                ;;
            *)
                warn "Invalid choice"
                ;;
        esac
    done
    rm -f "$tmp_live"
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

# ── Deploy config files (interactive) ────────────────────────────────────────

deploy_config_file "${SCRIPT_DIR}/${ENV_EXAMPLE}"  "${ENV_DEST}"  "root:wazuh" "640" "${ENV_EXAMPLE}"
deploy_config_file "${SCRIPT_DIR}/${YAML_EXAMPLE}" "${YAML_DEST}" "root:wazuh" "640" "${YAML_EXAMPLE}"

# ── Drop latest example files + check for new keys ──────────────────────────

info "Updating example files alongside live configs"
copy_file "${SCRIPT_DIR}/${ENV_EXAMPLE}" "${ENV_DEST}.example"
run_cmd "sudo chmod 644 ${ENV_DEST}.example"
copy_file "${SCRIPT_DIR}/${YAML_EXAMPLE}" "${YAML_DEST}.example"
run_cmd "sudo chmod 644 ${YAML_DEST}.example"

# Compare env keys (variable names before '=')
# Note: live env file is mode 640 root-owned, so sudo is needed to read it
env_exists=$(run_cmd "test -f ${ENV_DEST} && echo yes || echo no" 2>/dev/null || echo "no")
if [[ "$DRY_RUN" != true && "$env_exists" == "yes" ]]; then
    diff_cmd="comm -23 <(grep -oP '^[A-Z_]+(?==)' ${ENV_DEST}.example | sort) <(sudo grep -oP '^[A-Z_]+(?==)' ${ENV_DEST} | sort)"
    if [[ -n "$TARGET" ]]; then
        new_env_keys=$(ssh "$TARGET" "sudo bash -c '$diff_cmd'" 2>/dev/null || true)
    else
        new_env_keys=$(sudo bash -c "$diff_cmd" 2>/dev/null || true)
    fi
    if [[ -n "$new_env_keys" ]]; then
        warn "New env keys available in ${ENV_DEST}.example:"
        while IFS= read -r key; do
            warn "  $key"
        done <<< "$new_env_keys"
        warn "Review: diff ${ENV_DEST} ${ENV_DEST}.example"
    fi
fi

# Compare YAML top-level keys
yaml_exists=$(run_cmd "test -f ${YAML_DEST} && echo yes || echo no" 2>/dev/null || echo "no")
if [[ "$DRY_RUN" != true && "$yaml_exists" == "yes" ]]; then
    diff_cmd="comm -23 <(grep -oP '^[a-z_]+(?=:)' ${YAML_DEST}.example | sort) <(sudo grep -oP '^[a-z_]+(?=:)' ${YAML_DEST} | sort)"
    if [[ -n "$TARGET" ]]; then
        new_yaml_keys=$(ssh "$TARGET" "sudo bash -c '$diff_cmd'" 2>/dev/null || true)
    else
        new_yaml_keys=$(sudo bash -c "$diff_cmd" 2>/dev/null || true)
    fi
    if [[ -n "$new_yaml_keys" ]]; then
        warn "New YAML sections available in ${YAML_DEST}.example:"
        while IFS= read -r key; do
            warn "  $key"
        done <<< "$new_yaml_keys"
        warn "Review: diff ${YAML_DEST} ${YAML_DEST}.example"
    fi
fi

# ── Check ossec.conf for required entries ────────────────────────────────────

OSSEC_CONF="/var/ossec/etc/ossec.conf"

if [[ "$DRY_RUN" != true ]]; then
    ossec_exists=$(run_cmd "test -f ${OSSEC_CONF} && echo yes || echo no" 2>/dev/null || echo "no")
    if [[ "$ossec_exists" == "yes" ]]; then
        missing=()
        has_integration=$(run_cmd "grep -q 'custom-telegram' ${OSSEC_CONF} && echo yes || echo no" 2>/dev/null || echo "no")
        has_command=$(run_cmd "grep -q 'notify-ban' ${OSSEC_CONF} && echo yes || echo no" 2>/dev/null || echo "no")

        [[ "$has_integration" != "yes" ]] && missing+=("custom-telegram integration")
        [[ "$has_command" != "yes" ]]     && missing+=("notify-ban command/active-response")

        if [[ ${#missing[@]} -gt 0 ]]; then
            echo ""
            warn "ossec.conf is missing required entries:"
            for entry in "${missing[@]}"; do
                warn "  • ${entry}"
            done
            warn "See ossec-snippet.conf for the XML blocks to add to ${OSSEC_CONF}"
            warn "Then restart: sudo systemctl restart wazuh-manager"
        else
            info "ossec.conf: integration + active response entries found ✓"
        fi
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

# ── Register bot commands with Telegram ──────────────────────────────────────

PYTHON_BIN="/var/ossec/framework/python/bin/python3"
COMMANDER="${FILES["telegram-commander.py"]}"

if [[ "$DRY_RUN" == true ]]; then
    echo "  (dry-run) register bot commands"
else
    info "Registering bot commands with Telegram..."
    register_cmd="set -a && source ${ENV_DEST} && set +a && ${PYTHON_BIN} ${COMMANDER} --register-commands"
    if [[ -n "$TARGET" ]]; then
        ssh "$TARGET" "sudo bash -c '$register_cmd'" && info "Bot commands registered ✓" || warn "Command registration failed — run manually after fixing env vars"
    else
        sudo bash -c "$register_cmd" && info "Bot commands registered ✓" || warn "Command registration failed — run manually after fixing env vars"
    fi
fi
