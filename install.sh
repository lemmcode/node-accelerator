#!/usr/bin/env bash
#
# node-accelerator — ⚡ оптимизатор + 🩺 диагностика + 🛡 защита Remnawave/VPN-ноды.
#
#   sudo bash install.sh              — меню
#   sudo bash install.sh optimize     — ⚡ XanMod+BBRv3 + тюнинг
#   sudo bash install.sh protect      — 🛡 nftables + CrowdSec
#   sudo bash install.sh diagnose     — 🩺 диагностика (read-only)
#   sudo bash install.sh all          — optimize → protect → diagnose
#   sudo bash install.sh rollback [optimize|protect|all]
#
# curl-bash:
#   curl -fsSL https://raw.githubusercontent.com/jestivald/node-accelerator/main/install.sh | sudo bash -s all
#   # прод: пиньте тег (компрометация ветки main тогда не утечёт сразу на весь флот):
#   export NA_REF=v2.1; curl -fsSL "https://raw.githubusercontent.com/jestivald/node-accelerator/$NA_REF/install.sh" | sudo -E bash -s all

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPTS="$SCRIPT_DIR/scripts"
# NA_REF — ветка/тег для curl|bash-режима (по умолчанию main). Для прода пиньте тег.
NA_REF="${NA_REF:-main}"
REPO_URL="${NA_REPO_URL:-https://raw.githubusercontent.com/jestivald/node-accelerator/$NA_REF}"

# curl|bash — подтянуть модули
if [[ ! -d "$SCRIPTS" ]]; then
    SCRIPTS="$(mktemp -d)/scripts"; mkdir -p "$SCRIPTS/lib"
    echo "[*] Скачиваю модули из $REPO_URL ..."
    for f in lib/common.sh optimize.sh protect.sh diagnose.sh rollback.sh; do
        curl -fsSL "$REPO_URL/scripts/$f" -o "$SCRIPTS/$f" || { echo "[x] Не скачал $f"; exit 1; }
    done
fi

# shellcheck source=scripts/lib/common.sh
. "$SCRIPTS/lib/common.sh"
require_root
detect_os

run_optimize() { bash "$SCRIPTS/optimize.sh"; }
run_protect()  { bash "$SCRIPTS/protect.sh"; }
run_diagnose() { bash "$SCRIPTS/diagnose.sh"; }
run_rollback() { bash "$SCRIPTS/rollback.sh" "${1:-all}"; }

show_menu() {
    clear 2>/dev/null || true
    cat <<'BANNER'
┌────────────────────────────────────────────────────┐
│            ⚡ node-accelerator ⚡                    │
│   Оптимизация · Диагностика · Защита VPN-ноды       │
├────────────────────────────────────────────────────┤
│                                                      │
│   1) ⚡ Оптимизатор                                  │
│        XanMod (BBRv3) + sysctl + RPS/RFS +           │
│        лимиты + swap + NIC + governor                │
│                                                      │
│   2) 🛡 Защита                                       │
│        nftables (AntiScan/flag-drop/anti-spoof/      │
│        SYN+UDP-flood/ssh-flood) + CrowdSec bouncer   │
│                                                      │
│   3) 🩺 Диагностика (read-only)                      │
│                                                      │
│   4) 🚀 Всё сразу (1 → 2 → 3)                        │
│                                                      │
│   5) ↩️  Откат                                       │
│                                                      │
│   0) Выход                                           │
│                                                      │
└────────────────────────────────────────────────────┘
BANNER
    read -r -p "Выбор: " choice
    case "$choice" in
        1) run_optimize ;;
        2) run_protect ;;
        3) run_diagnose ;;
        4) run_optimize; run_protect; run_diagnose ;;
        5)
            echo "  a) optimize   b) protect   c) всё"
            read -r -p "Что откатить? [c]: " r
            case "$r" in a|A) run_rollback optimize ;; b|B) run_rollback protect ;; *) run_rollback all ;; esac
            ;;
        0) exit 0 ;;
        *) warn "Неверный выбор" ;;
    esac
}

case "${1:-}" in
    optimize) run_optimize ;;
    protect)  run_protect ;;
    diagnose|diag) run_diagnose ;;
    all)      run_optimize; run_protect; run_diagnose ;;
    rollback) run_rollback "${2:-all}" ;;
    "")       show_menu ;;
    -h|--help) sed -n '2,18p' "$0" ;;
    *) err "Неизвестная команда: $1"; sed -n '2,18p' "$0"; exit 1 ;;
esac
