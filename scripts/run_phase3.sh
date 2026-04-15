#!/usr/bin/env bash
# =============================================================================
# run_phase3.sh — Fase 3: Análisis de binarios y firmware
#
# Herramientas:
#   1. Grype       (grype dir:build/)
#   2. CVE-Binary-Tool (NIST)
#   3. Trivy       (trivy fs build/)
#
# Prerequisito: cmake --build build (binario compilado)
# Output: tests/sca_results/phase3_*.json
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$ROOT_DIR/build"
RESULTS_DIR="$ROOT_DIR/tests/sca_results"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; BLUE='\033[0;34m'; NC='\033[0m'
log_ok()    { echo -e "${GREEN}[OK]${NC}      $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}    $*"; }
log_error() { echo -e "${RED}[ERROR]${NC}   $*"; }
log_info()  { echo -e "${BLUE}[INFO]${NC}    $*"; }
log_skip()  { echo -e "[SKIP]    $*"; }

mkdir -p "$RESULTS_DIR"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# Verificar que el binario existe
BINARY=$(find "$BUILD_DIR" -name "mi-gateway" -o -name "mi-gateway.elf" 2>/dev/null | head -1)
if [ -z "$BINARY" ]; then
    log_error "Binario no encontrado en $BUILD_DIR"
    echo "Compila primero con:"
    echo "  cmake -B build && cmake --build build"
    exit 1
fi

log_info "Binario encontrado: $BINARY"
file "$BINARY" || true

echo ""
echo "============================================================"
echo "  FASE 3: Análisis de binarios y firmware"
echo "  Binario: $BINARY"
echo "  Directorio: $BUILD_DIR"
echo "  Resultados: $RESULTS_DIR"
echo "============================================================"
echo ""

# -----------------------------------------------------------------------------
# 1. GRYPE (análisis de directorio de binarios)
# -----------------------------------------------------------------------------
echo "--- [1/3] Grype (dir:build/) ---"
if command -v grype &>/dev/null; then
    log_info "Ejecutando Grype en directorio de build..."
    GRYPE_OUT="$RESULTS_DIR/phase3_grype_${TIMESTAMP}.json"
    GRYPE_LOG="$RESULTS_DIR/phase3_grype_${TIMESTAMP}.log"
    grype "dir:$BUILD_DIR" \
        --output json \
        --add-cpes-if-none \
        > "$GRYPE_OUT" 2> "$GRYPE_LOG" && \
    log_ok "Grype completado → $GRYPE_OUT" || \
    log_error "Grype falló"

    # También analiza el binario directamente
    GRYPE_BIN_OUT="$RESULTS_DIR/phase3_grype_binary_${TIMESTAMP}.json"
    GRYPE_BIN_LOG="$RESULTS_DIR/phase3_grype_binary_${TIMESTAMP}.log"
    grype "$BINARY" \
        --output json \
        > "$GRYPE_BIN_OUT" 2> "$GRYPE_BIN_LOG" && \
    log_ok "Grype (binario directo) → $GRYPE_BIN_OUT" || true

    cp "$GRYPE_OUT" "$RESULTS_DIR/phase3_grype_latest.json"
else
    log_skip "Grype no instalado."
fi

# -----------------------------------------------------------------------------
# 2. CVE-BINARY-TOOL (NIST)
# -----------------------------------------------------------------------------
echo ""
echo "--- [2/3] CVE-Binary-Tool ---"
if command -v cve-bin-tool &>/dev/null || python3 -c "import cve_bin_tool" &>/dev/null; then
    CVE_CMD="cve-bin-tool"
    python3 -c "import cve_bin_tool" &>/dev/null && CVE_CMD="python3 -m cve_bin_tool.cli"

    log_info "Ejecutando CVE-Binary-Tool..."
    CBT_OUT="$RESULTS_DIR/phase3_cbt_${TIMESTAMP}.json"

    # Evita fuente RSD (requiere gsutil en algunos entornos) y usa mirror NVD.
    CBT_COMMON_ARGS=(
        --nvd json-mirror
        --disable-data-source RSD,EPSS,OSV,GAD,REDHAT,CURL,PURL2CPE
        --disable-version-check
        --format json
    )

    # Analiza el directorio de build. Exit code >0 puede significar CVEs encontradas.
    set +e
    $CVE_CMD \
        "${CBT_COMMON_ARGS[@]}" \
        --update latest \
        --output-file "$CBT_OUT" \
        "$BUILD_DIR" > "$RESULTS_DIR/phase3_cbt_${TIMESTAMP}.log" 2>&1
    CBT_RC=$?
    set -e
    tail -10 "$RESULTS_DIR/phase3_cbt_${TIMESTAMP}.log" || true

    if [ -s "$CBT_OUT" ]; then
        if [ "$CBT_RC" -eq 0 ]; then
            log_ok "CVE-Binary-Tool completado (sin hallazgos) → $CBT_OUT"
        elif [ "$CBT_RC" -gt 0 ] && [ "$CBT_RC" -le 125 ]; then
            log_ok "CVE-Binary-Tool completado (hallazgos detectados) → $CBT_OUT"
        else
            log_warn "CVE-Binary-Tool devolvió código $CBT_RC pero generó salida JSON utilizable → $CBT_OUT"
        fi
    else
        log_error "CVE-Binary-Tool falló y no generó salida JSON"
    fi

    # También analiza el binario directamente
    CBT_BIN_OUT="$RESULTS_DIR/phase3_cbt_binary_${TIMESTAMP}.json"
    set +e
    $CVE_CMD \
        "${CBT_COMMON_ARGS[@]}" \
        --update never \
        --output-file "$CBT_BIN_OUT" \
        "$BINARY" > "$RESULTS_DIR/phase3_cbt_binary_${TIMESTAMP}.log" 2>&1
    CBT_BIN_RC=$?
    set -e
    tail -5 "$RESULTS_DIR/phase3_cbt_binary_${TIMESTAMP}.log" || true
    [ "$CBT_BIN_RC" -gt 125 ] && log_warn "CVE-Binary-Tool (binario directo) devolvió código $CBT_BIN_RC"

    cp "$CBT_OUT" "$RESULTS_DIR/phase3_cbt_latest.json" 2>/dev/null || true
else
    log_skip "CVE-Binary-Tool no instalado. Instala con: pip install cve-bin-tool"
fi

# -----------------------------------------------------------------------------
# 3. TRIVY (análisis de filesystem)
# -----------------------------------------------------------------------------
echo ""
echo "--- [3/3] Trivy (fs) ---"
if command -v trivy &>/dev/null; then
    log_info "Ejecutando Trivy en directorio de build (modo binario puro)..."
    TRIVY_OUT="$RESULTS_DIR/phase3_trivy_${TIMESTAMP}.json"
    trivy fs \
        --format json \
        --output "$TRIVY_OUT" \
        --scanners vuln \
        "$BUILD_DIR" 2>&1 | tail -5 && \
    log_ok "Trivy completado → $TRIVY_OUT" || \
    log_error "Trivy falló"

    cp "$TRIVY_OUT" "$RESULTS_DIR/phase3_trivy_latest.json"
else
    log_skip "Trivy no instalado. Instala con: curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh"
fi

echo ""
echo "============================================================"
echo "  Fase 3 completada"
echo "  Para calcular métricas: python3 scripts/calculate_metrics.py --phase 3"
echo "============================================================"
