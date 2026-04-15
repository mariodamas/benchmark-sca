#!/usr/bin/env bash
# ============================================================
# run_all_phases.sh - Ejecuta las fases del benchmark SCA
# con medicion de tiempos y EMBA opcional.
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJ="$(dirname "$SCRIPT_DIR")"
RES="$PROJ/tests/sca_results"
SBOM="$PROJ/sbom/sbom-cyclonedx.json"
BIN="$PROJ/build/mi-gateway"
LIB="$PROJ/lib"
DC_SH="/tmp/dependency-check/bin/dependency-check.sh"
DC_DATA="/tmp/dc-data"
DC_OUT="/tmp/dc_results"
EMBA_SCRIPT="$PROJ/scripts/run_phase3_emba.sh"

if [ -f "$PROJ/.env.local" ]; then
    # shellcheck disable=SC1091
    set -a
    source "$PROJ/.env.local"
    set +a

    # Windows CRLF in .env.local can leak '\r' into tokens and break HTTP headers.
    for var in SNYK_TOKEN FOSSA_API_KEY DTRACK_API_KEY DTRACK_URL DTRACK_PROJECT DTRACK_VERSION SNYK_ORG; do
        if [ -n "${!var:-}" ]; then
            printf -v "$var" '%s' "${!var//$'\r'/}"
        fi
    done
fi

TS=$(date +%Y%m%d_%H%M%S)
LOG="$PROJ/docs/run_all_phases_${TS}.log"

mkdir -p "$RES" "$PROJ/sbom" "$DC_DATA" "$DC_OUT"

log() { echo "[$(date '+%H:%M:%S')] $*" | tee -a "$LOG"; }

run_and_time() {
    local out_var="$1"
    local label="$2"
    shift 2

    local t0=$SECONDS
    "$@" 2>>"$LOG" || true
    local elapsed=$((SECONDS - t0))

    printf -v "$out_var" '%s' "$elapsed"
    log "  => $label: ${elapsed}s"
}

log "=== BENCHMARK SCA - EJECUCION COMPLETA $TS ==="
log "PROJ=$PROJ"
log "BIN=$BIN"
log "SBOM=$SBOM"
log "SNYK_TOKEN presente: $([ -n "${SNYK_TOKEN:-}" ] && echo SI || echo NO)"

# ============================================================
# FASE 1 - SBOM
# ============================================================
log ">>> FASE 1: SBOM"

SYFT_T=0
if command -v syft >/dev/null 2>&1; then
    run_and_time SYFT_T "syft" syft dir:"$PROJ" -o cyclonedx-json --file "$SBOM" --quiet
else
    log "  => syft no instalado; se mantiene SBOM existente"
fi

GRYPE1_T=0
if command -v grype >/dev/null 2>&1 && [ -f "$SBOM" ]; then
    run_and_time GRYPE1_T "grype" grype "sbom:$SBOM" -o json --file "$RES/phase1_grype_${TS}.json"
    [ -f "$RES/phase1_grype_${TS}.json" ] && cp "$RES/phase1_grype_${TS}.json" "$RES/phase1_grype_latest.json"
else
    log "  => grype no instalado o SBOM inexistente"
fi

TRIVY1_T=0
if command -v trivy >/dev/null 2>&1 && [ -f "$SBOM" ]; then
    run_and_time TRIVY1_T "trivy" trivy sbom "$SBOM" --format json --output "$RES/trivy_fase1_sbom_${TS}.json" --quiet
    [ -f "$RES/trivy_fase1_sbom_${TS}.json" ] && cp "$RES/trivy_fase1_sbom_${TS}.json" "$RES/trivy_fase1_sbom.json"
else
    log "  => trivy no instalado o SBOM inexistente"
fi

SNYK1_T=0
if command -v snyk >/dev/null 2>&1 && [ -n "${SNYK_TOKEN:-}" ]; then
    if [ -f "$PROJ/vcpkg.json" ]; then
        run_and_time SNYK1_T "snyk phase1" snyk test --json --file="$PROJ/vcpkg.json" --package-manager=vcpkg
        snyk test --json --file="$PROJ/vcpkg.json" --package-manager=vcpkg > "$RES/phase1_snyk_${TS}.json" 2>>"$LOG" || true
    else
        run_and_time SNYK1_T "snyk phase1" snyk test --json --file="$PROJ/CMakeLists.txt" --project-name=mi-gateway-iot
        snyk test --json --file="$PROJ/CMakeLists.txt" --project-name=mi-gateway-iot > "$RES/phase1_snyk_${TS}.json" 2>>"$LOG" || true
    fi
    [ -f "$RES/phase1_snyk_${TS}.json" ] && cp "$RES/phase1_snyk_${TS}.json" "$RES/phase1_snyk_latest.json"
else
    log "  => snyk no instalado o SNYK_TOKEN no definido"
fi

log ">>> FASE 1 TIEMPOS: syft=${SYFT_T}s grype=${GRYPE1_T}s trivy=${TRIVY1_T}s snyk=${SNYK1_T}s"

# ============================================================
# FASE 2 - VENDORING
# ============================================================
log ">>> FASE 2: VENDORING"

SNYK2_T=0
if command -v snyk >/dev/null 2>&1 && [ -n "${SNYK_TOKEN:-}" ] && [ -d "$LIB" ]; then
    run_and_time SNYK2_T "snyk unmanaged" snyk test --unmanaged --json "$LIB"
    snyk test --unmanaged --json "$LIB" > "$RES/phase2_snyk_${TS}.json" 2>>"$LOG" || true
    [ -f "$RES/phase2_snyk_${TS}.json" ] && cp "$RES/phase2_snyk_${TS}.json" "$RES/phase2_snyk_latest.json"
else
    log "  => snyk no instalado, token ausente o lib/ inexistente"
fi

DC_T=0
if [ -f "$DC_SH" ] && [ -d "$LIB" ]; then
    local_t0=$SECONDS
    "$DC_SH" \
        --project "mi-gateway-iot" \
        --scan "$LIB" \
        --enableExperimental \
        --format JSON \
        --out "$DC_OUT" \
        --data "$DC_DATA" \
        --disableAssembly \
        2>>"$LOG" || true
    DC_T=$((SECONDS - local_t0))
    if [ -f "$DC_OUT/dependency-check-report.json" ]; then
        cp "$DC_OUT/dependency-check-report.json" "$RES/phase2_dc_${TS}.json"
        cp "$DC_OUT/dependency-check-report.json" "$RES/phase2_dc_latest.json"
        log "  => OWASP DC: ${DC_T}s"
    else
        DC_T=0
        log "  => OWASP DC sin resultado util"
    fi
else
    log "  => OWASP DC no instalado o lib/ inexistente"
fi

log ">>> FASE 2 TIEMPOS: snyk_unmanaged=${SNYK2_T}s owasp_dc=${DC_T}s"

# ============================================================
# FASE 3 - BINARIO
# ============================================================
log ">>> FASE 3: BINARIO"

CBT_T=0
if command -v cve-bin-tool >/dev/null 2>&1 && [ -f "$BIN" ]; then
    run_and_time CBT_T "cve-bin-tool" cve-bin-tool --format json --disable-data-source RSD,EPSS,OSV,GAD,REDHAT,CURL,PURL2CPE --output-file "$RES/phase3_cbt_${TS}.json" "$BIN"
    [ -f "$RES/phase3_cbt_${TS}.json" ] && cp "$RES/phase3_cbt_${TS}.json" "$RES/phase3_cbt_latest.json"
else
    log "  => cve-bin-tool no instalado o binario inexistente"
fi

GRYPE3_T=0
if command -v grype >/dev/null 2>&1 && [ -f "$BIN" ]; then
    run_and_time GRYPE3_T "grype binary" grype "$BIN" -o json --file "$RES/phase3_grype_${TS}.json"
    [ -f "$RES/phase3_grype_${TS}.json" ] && cp "$RES/phase3_grype_${TS}.json" "$RES/phase3_grype_latest.json"
else
    log "  => grype no instalado o binario inexistente"
fi

TRIVY3_T=0
if command -v trivy >/dev/null 2>&1 && [ -f "$BIN" ]; then
    run_and_time TRIVY3_T "trivy binary" trivy rootfs "$BIN" --format json --output "$RES/phase3_trivy_${TS}.json" --quiet
    [ -f "$RES/phase3_trivy_${TS}.json" ] && cp "$RES/phase3_trivy_${TS}.json" "$RES/phase3_trivy_latest.json"
else
    log "  => trivy no instalado o binario inexistente"
fi

# ============================================================
# FASE 3B - EMBA (OPCIONAL)
# ============================================================
EMBA_T=0
log ">>> FASE 3B: EMBA (opcional)"
if [ -f "$EMBA_SCRIPT" ]; then
    local_t0=$SECONDS
    bash "$EMBA_SCRIPT" --binary "$BIN" --results-dir "$RES" 2>>"$LOG" || true
    EMBA_T=$((SECONDS - local_t0))
    log "  => emba: ${EMBA_T}s"
else
    log "  => script EMBA no encontrado: $EMBA_SCRIPT"
fi

# ============================================================
# RESUMEN
# ============================================================
TOTAL=$((SYFT_T + GRYPE1_T + TRIVY1_T + SNYK1_T + SNYK2_T + DC_T + CBT_T + GRYPE3_T + TRIVY3_T + EMBA_T))

log "========================================================"
log "RESUMEN TIEMPOS"
log "========================================================"
log "FASE 1: syft=${SYFT_T}s grype=${GRYPE1_T}s trivy=${TRIVY1_T}s snyk=${SNYK1_T}s"
log "FASE 2: snyk_unmanaged=${SNYK2_T}s owasp_dc=${DC_T}s"
log "FASE 3: cbt=${CBT_T}s grype=${GRYPE3_T}s trivy=${TRIVY3_T}s emba=${EMBA_T}s"
log "TOTAL PIPELINE: ${TOTAL}s"

python3 - <<PYEOF
import json

times = {
    "timestamp": "${TS}",
    "phase1": {
        "syft_sbom_gen": {"seconds": ${SYFT_T}, "tool": "syft"},
        "grype_sbom": {"seconds": ${GRYPE1_T}, "tool": "grype"},
        "trivy_sbom": {"seconds": ${TRIVY1_T}, "tool": "trivy"},
        "snyk_phase1": {"seconds": ${SNYK1_T}, "tool": "snyk"}
    },
    "phase2": {
        "snyk_unmanaged": {"seconds": ${SNYK2_T}, "tool": "snyk --unmanaged"},
        "owasp_dc": {"seconds": ${DC_T}, "tool": "owasp-dc"}
    },
    "phase3": {
        "cve_bin_tool": {"seconds": ${CBT_T}, "tool": "cve-bin-tool"},
        "grype_binary": {"seconds": ${GRYPE3_T}, "tool": "grype"},
        "trivy_binary": {"seconds": ${TRIVY3_T}, "tool": "trivy"},
        "emba_optional": {"seconds": ${EMBA_T}, "tool": "EMBA"}
    },
    "total_seconds": ${TOTAL}
}

out = "${PROJ}/docs/tool_execution_times.json"
with open(out, "w", encoding="utf-8") as f:
    json.dump(times, f, indent=2)
print(f"Tiempos guardados en {out}")
PYEOF

log "Resultados en: $RES"
log "Log completo: $LOG"
