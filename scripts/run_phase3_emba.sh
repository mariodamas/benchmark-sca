#!/usr/bin/env bash
# =============================================================================
# run_phase3_emba.sh - Fase 3B: analisis EMBA (opcional)
#
# Este script no rompe el pipeline si Docker/EMBA no estan disponibles.
# Genera un JSON de estado para trazabilidad.
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
RESULTS_DIR="$ROOT_DIR/tests/sca_results"
BINARY="$ROOT_DIR/build/mi-gateway"
FORCE_MODE=0
TIMEOUT_SECONDS="${EMBA_TIMEOUT_SECONDS:-600}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --binary)
            BINARY="$2"
            shift 2
            ;;
        --results-dir)
            RESULTS_DIR="$2"
            shift 2
            ;;
        --force)
            FORCE_MODE=1
            shift
            ;;
        --timeout-seconds)
            TIMEOUT_SECONDS="$2"
            shift 2
            ;;
        *)
            echo "Parametro no reconocido: $1"
            exit 1
            ;;
    esac
done

if ! [[ "$TIMEOUT_SECONDS" =~ ^[0-9]+$ ]]; then
    echo "Valor invalido para --timeout-seconds: $TIMEOUT_SECONDS"
    exit 1
fi

mkdir -p "$RESULTS_DIR"
TS=$(date +%Y%m%d_%H%M%S)
OUT_JSON="$RESULTS_DIR/phase3_emba_${TS}.json"
OUT_LOG="$RESULTS_DIR/phase3_emba_${TS}.log"
LATEST_JSON="$RESULTS_DIR/phase3_emba_latest.json"

status="blocked"
reason=""
emba_cmd=""
emba_root=""
report_path=""
install_hint=""

if [ ! -f "$BINARY" ]; then
    reason="binary_not_found"
elif ! command -v docker >/dev/null 2>&1; then
    reason="docker_missing"
elif ! docker info >/dev/null 2>&1; then
    reason="docker_unavailable"
elif [ -x "$HOME/tools/emba/emba" ]; then
    emba_cmd="$HOME/tools/emba/emba"
elif command -v emba >/dev/null 2>&1; then
    emba_cmd="emba"
elif [ -x "$ROOT_DIR/emba/emba" ]; then
    emba_cmd="$ROOT_DIR/emba/emba"
elif [ -x "$HOME/emba/emba" ]; then
    emba_cmd="$HOME/emba/emba"
else
    reason="emba_missing"
    install_hint="clone_or_install_emba"
fi

if [ -n "$emba_cmd" ]; then
    if [ "$emba_cmd" = "emba" ]; then
        emba_resolved="$(command -v emba || true)"
    else
        emba_resolved="$emba_cmd"
    fi

    if [ -n "$emba_resolved" ]; then
        emba_root="$(dirname "$emba_resolved")"
    fi

    OUT_DIR="$RESULTS_DIR/emba_out_${TS}"
    mkdir -p "$OUT_DIR"

    emba_args=( -f "$BINARY" -l "$OUT_DIR" -s )
    if [ "$FORCE_MODE" -eq 1 ]; then
        emba_args+=( -F )
    fi

    set +e
    if [ -n "$emba_root" ] && [ -d "$emba_root" ]; then
        (
            cd "$emba_root"
            if [ "$TIMEOUT_SECONDS" -gt 0 ] && command -v timeout >/dev/null 2>&1; then
                timeout --signal=TERM --kill-after=30s "${TIMEOUT_SECONDS}s" ./emba "${emba_args[@]}"
            else
                ./emba "${emba_args[@]}"
            fi
        ) > "$OUT_LOG" 2>&1
    else
        if [ "$TIMEOUT_SECONDS" -gt 0 ] && command -v timeout >/dev/null 2>&1; then
            timeout --signal=TERM --kill-after=30s "${TIMEOUT_SECONDS}s" "$emba_cmd" "${emba_args[@]}" > "$OUT_LOG" 2>&1
        else
            "$emba_cmd" "${emba_args[@]}" > "$OUT_LOG" 2>&1
        fi
    fi
    rc=$?
    set -e

    report_path="$OUT_DIR"
    if [ "$rc" -eq 0 ]; then
        status="ok"
        reason="executed"
    elif [ "$rc" -eq 124 ]; then
        status="timeout"
        reason="emba_timeout_${TIMEOUT_SECONDS}s"
    else
        status="error"
        reason="emba_exit_${rc}"
    fi
else
    if [ "$reason" = "docker_missing" ] || [ "$reason" = "docker_unavailable" ]; then
        install_hint="install_docker_desktop_and_enable_wsl_integration"
    fi
    {
        echo "EMBA no ejecutado. Estado: $reason"
        echo "Requisitos minimos: Docker operativo + EMBA instalado"
        if [ -n "$install_hint" ]; then
            echo "Hint: $install_hint"
        fi
    } > "$OUT_LOG"
fi

python3 - <<PYEOF
import json

payload = {
    "tool": "EMBA",
    "status": "${status}",
    "reason": "${reason}",
    "binary": "${BINARY}",
    "force_mode": ${FORCE_MODE},
    "timeout_seconds": ${TIMEOUT_SECONDS},
    "report_path": "${report_path}",
    "emba_cmd": "${emba_cmd}",
    "emba_root": "${emba_root}",
    "install_hint": "${install_hint}",
    "log_file": "${OUT_LOG}",
    "timestamp": "${TS}"
}

with open("${OUT_JSON}", "w", encoding="utf-8") as f:
    json.dump(payload, f, indent=2)
with open("${LATEST_JSON}", "w", encoding="utf-8") as f:
    json.dump(payload, f, indent=2)

print("EMBA status saved to ${OUT_JSON}")
PYEOF
