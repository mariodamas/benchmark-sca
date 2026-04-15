#!/usr/bin/env bash
# =============================================================================
# run_phase2.sh — Fase 2: Identificación en código fuente / TPLs
#
# Herramientas:
#   1. Snyk CLI --unmanaged    (análisis C/C++ sin manifiesto)
#   2. FOSSA CLI               (beta C/C++)
#   3. ORT (OSS Review Toolkit)
#   4. scancode-toolkit
#
# Output: tests/sca_results/phase2_*.json
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
RESULTS_DIR="$ROOT_DIR/tests/sca_results"

# Load local defaults for API keys / tokens if present.
if [ -f "$ROOT_DIR/.env.local" ]; then
    # shellcheck disable=SC1091
    set -a
    source "$ROOT_DIR/.env.local"
    set +a
fi

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; BLUE='\033[0;34m'; NC='\033[0m'
log_ok()    { echo -e "${GREEN}[OK]${NC}      $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}    $*"; }
log_error() { echo -e "${RED}[ERROR]${NC}   $*"; }
log_info()  { echo -e "${BLUE}[INFO]${NC}    $*"; }
log_skip()  { echo -e "[SKIP]    $*"; }

sanitize_json_file() {
    local file_path="$1"
    python3 - "$file_path" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8", errors="ignore").lstrip("\ufeff\n\r\t ")
decoder = json.JSONDecoder()
obj, _ = decoder.raw_decode(text)
path.write_text(json.dumps(obj, ensure_ascii=False), encoding="utf-8")
print("ok")
PY
}

mkdir -p "$RESULTS_DIR"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

echo ""
echo "============================================================"
echo "  FASE 2: Análisis de código fuente y TPLs"
echo "  Directorio: $ROOT_DIR"
echo "  Resultados: $RESULTS_DIR"
echo "============================================================"
echo ""

# -----------------------------------------------------------------------------
# 1. SNYK CLI --unmanaged
#    Analiza carpetas C/C++ sin manifiesto, detecta TPLs por hash
# -----------------------------------------------------------------------------
echo "--- [1/4] Snyk CLI --unmanaged ---"
if command -v snyk &>/dev/null; then
    if [ -z "${SNYK_TOKEN:-}" ]; then
        log_warn "SNYK_TOKEN no definido."
        log_skip "Snyk omitido"
    else
        log_info "Ejecutando Snyk --unmanaged en lib/ ..."
        SNYK_OUT="$RESULTS_DIR/phase2_snyk_unmanaged_${TIMESTAMP}.json"

        # Snyk --unmanaged analiza cada subdirectorio de lib/ por separado
        SNYK_COMBINED="[]"
        for lib_subdir in "$ROOT_DIR/lib"/*/; do
            lib_name=$(basename "$lib_subdir")
            log_info "  Analizando $lib_name ..."
            SNYK_PARTIAL="$RESULTS_DIR/phase2_snyk_${lib_name}_${TIMESTAMP}.json"
            snyk test --unmanaged \
                --json \
                "$lib_subdir" \
                > "$SNYK_PARTIAL" 2>&1 || true
            log_ok "  $lib_name → $SNYK_PARTIAL"
        done

        # Combina resultados (requiere jq)
        if command -v jq &>/dev/null; then
            jq -s '.' "$RESULTS_DIR/phase2_snyk_"*"_${TIMESTAMP}.json" \
                > "$SNYK_OUT" 2>/dev/null || true
        fi
        log_ok "Snyk --unmanaged completado → $RESULTS_DIR/phase2_snyk_*"
        cp "$SNYK_OUT" "$RESULTS_DIR/phase2_snyk_latest.json" 2>/dev/null || true
    fi
else
    log_skip "Snyk CLI no instalado."
fi

# -----------------------------------------------------------------------------
# 2. FOSSA CLI (beta C/C++)
# -----------------------------------------------------------------------------
echo ""
echo "--- [2/4] FOSSA CLI ---"
if command -v fossa &>/dev/null; then
    if [ -z "${FOSSA_API_KEY:-}" ]; then
        log_warn "FOSSA_API_KEY no definido."
        log_skip "FOSSA omitido"
    else
        FOSSA_PROJECT="mi-gateway-iot-benchmark"
        if command -v git &>/dev/null && git -C "$ROOT_DIR" rev-parse --short HEAD &>/dev/null; then
            FOSSA_REVISION="$(git -C "$ROOT_DIR" rev-parse --short HEAD)"
        else
            FOSSA_REVISION="local-${TIMESTAMP}"
        fi

        log_info "Ejecutando FOSSA analyze (upload + output)..."
        FOSSA_OUT="$RESULTS_DIR/phase2_fossa_${TIMESTAMP}.json"
        cd "$ROOT_DIR"
        fossa analyze \
            --project "$FOSSA_PROJECT" \
            --revision "$FOSSA_REVISION" \
            --detect-vendored \
            --x-vendetta \
            --tee-output > "$FOSSA_OUT" 2>&1 && \
        log_ok "FOSSA analyze completado → $FOSSA_OUT" || \
        log_error "FOSSA analyze falló"

        log_info "Ejecutando FOSSA test (CVEs remotos)..."
        FOSSA_TEST_OUT="$RESULTS_DIR/phase2_fossa_test_${TIMESTAMP}.json"
        set +e
        fossa test \
            --project "$FOSSA_PROJECT" \
            --revision "$FOSSA_REVISION" \
            --timeout 900 \
            --format json > "$FOSSA_TEST_OUT" 2>&1
        FOSSA_TEST_RC=$?
        set -e

        if sanitize_json_file "$FOSSA_TEST_OUT" >/dev/null 2>&1; then
            cp "$FOSSA_TEST_OUT" "$RESULTS_DIR/phase2_fossa_latest.json"
            if [ "$FOSSA_TEST_RC" -eq 0 ] || [ "$FOSSA_TEST_RC" -eq 1 ]; then
                log_ok "FOSSA test completado → $FOSSA_TEST_OUT"
            else
                log_warn "FOSSA test devolvió código $FOSSA_TEST_RC pero generó JSON utilizable."
            fi
        else
            log_warn "FOSSA test remoto no devolvió JSON parseable. Reintentando test local..."
            FOSSA_TEST_LOCAL_OUT="$RESULTS_DIR/phase2_fossa_test_local_${TIMESTAMP}.json"
            set +e
            fossa test --format json > "$FOSSA_TEST_LOCAL_OUT" 2>&1
            FOSSA_TEST_LOCAL_RC=$?
            set -e

            if sanitize_json_file "$FOSSA_TEST_LOCAL_OUT" >/dev/null 2>&1; then
                cp "$FOSSA_TEST_LOCAL_OUT" "$RESULTS_DIR/phase2_fossa_latest.json"
                if [ "$FOSSA_TEST_LOCAL_RC" -eq 0 ] || [ "$FOSSA_TEST_LOCAL_RC" -eq 1 ]; then
                    log_ok "FOSSA test local completado → $FOSSA_TEST_LOCAL_OUT"
                else
                    log_warn "FOSSA test local devolvió código $FOSSA_TEST_LOCAL_RC pero generó JSON utilizable."
                fi
            else
                if grep -qi "push-only API key" "$FOSSA_TEST_OUT"; then
                    log_warn "FOSSA está usando una API key push-only: hay conteo de issues, pero no detalle de CVEs en CLI."
                else
                    log_warn "FOSSA test no devolvió JSON parseable. Se mantiene salida raw en $FOSSA_TEST_OUT"
                fi
            python3 - "$FOSSA_OUT" "$FOSSA_TEST_OUT" "$RESULTS_DIR/phase2_fossa_latest.json" <<'PY'
import json
import re
import sys
from pathlib import Path

analyze_path = Path(sys.argv[1])
test_path = Path(sys.argv[2])
out_path = Path(sys.argv[3])

payload = {
    "issues": [],
    "_note": "fossa test failed or returned non-json",
    "analyze_excerpt": analyze_path.read_text(encoding="utf-8", errors="ignore")[:100000],
    "test_excerpt": test_path.read_text(encoding="utf-8", errors="ignore")[:100000],
}

test_text = payload["test_excerpt"]
if "push-only API key" in test_text:
    m = re.search(r"Number of issues found:\s*(\d+)", test_text)
    payload["_note"] = "fossa test used push-only API key; issue details unavailable in CLI"
    payload["issue_count"] = int(m.group(1)) if m else None

out_path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
PY
            fi
        fi
    fi
else
    log_skip "FOSSA CLI no instalado. Instala con: curl -H 'Cache-Control: no-cache' https://raw.githubusercontent.com/fossas/fossa-cli/master/install-latest.sh | bash"
fi

# -----------------------------------------------------------------------------
# 3. ORT (OSS Review Toolkit)
# -----------------------------------------------------------------------------
echo ""
echo "--- [3/4] ORT (OSS Review Toolkit) ---"
if command -v ort &>/dev/null || [ -f "$HOME/.ort/scripts/ort.sh" ]; then
    ORT_CMD="ort"
    [ -f "$HOME/.ort/scripts/ort.sh" ] && ORT_CMD="$HOME/.ort/scripts/ort.sh"

    ORT_OUT_DIR="$RESULTS_DIR/phase2_ort_${TIMESTAMP}"
    mkdir -p "$ORT_OUT_DIR"
    ORT_CONFIG="$ROOT_DIR/scripts/ort.phase2.yml"

    log_info "Ejecutando ORT analyze (config phase2: Unmanaged)..."
    if $ORT_CMD \
        -c "$ORT_CONFIG" \
        analyze \
        --input-dir "$ROOT_DIR" \
        --output-dir "$ORT_OUT_DIR" \
        --output-formats JSON 2>&1 | tail -20; then
        log_ok "ORT analyze completado → $ORT_OUT_DIR"
    else
        log_warn "ORT analyze falló o no soporta opciones usadas. Se omite ORT en esta ejecución."
    fi

    if [ -f "$ORT_OUT_DIR/analyzer-result.json" ]; then
        log_info "Ejecutando ORT advise (OSV)..."
        if $ORT_CMD \
            -c "$ORT_CONFIG" \
            advise \
            --ort-file "$ORT_OUT_DIR/analyzer-result.json" \
            --output-dir "$ORT_OUT_DIR" \
            --output-formats JSON \
            --advisors OSV 2>&1 | tail -20; then
            log_ok "ORT advise completado"
            if grep -q '"packages" : \[ \]' "$ORT_OUT_DIR/analyzer-result.json"; then
                log_warn "ORT no resolvió paquetes en este repo; no puede emitir advisories/CVEs en esta fase."
            fi
        else
            log_warn "ORT advise no disponible con la configuración actual. Se omite resultado ORT advisor."
        fi

        # Compatibilidad cruzada: guardar JSON latest sin symlink.
        if [ -f "$ORT_OUT_DIR/advisor-result.json" ]; then
            cp "$ORT_OUT_DIR/advisor-result.json" "$RESULTS_DIR/phase2_ort_latest.json"
            log_ok "ORT latest JSON actualizado → $RESULTS_DIR/phase2_ort_latest.json"
        else
            cp "$ORT_OUT_DIR/analyzer-result.json" "$RESULTS_DIR/phase2_ort_latest.json"
            log_warn "No hay advisor-result.json; se usa analyzer-result.json como latest ORT."
        fi
    fi
else
    log_skip "ORT no instalado. Ver: https://github.com/oss-review-toolkit/ort#installation"
fi

# -----------------------------------------------------------------------------
# 4. scancode-toolkit
# -----------------------------------------------------------------------------
echo ""
echo "--- [4/4] scancode-toolkit ---"
SCANCODE_CMD=""
if command -v scancode &>/dev/null; then
    SCANCODE_CMD="scancode"
elif [ -x "$HOME/.local/bin/scancode" ]; then
    SCANCODE_CMD="$HOME/.local/bin/scancode"
else
    log_info "scancode no encontrado. Intentando instalar con pip --user..."
    if command -v pipx &>/dev/null; then
        pipx install scancode-toolkit >/dev/null 2>&1 || true
        pipx ensurepath >/dev/null 2>&1 || true
    fi
    python3 -m pip install --user --upgrade scancode-toolkit >/dev/null 2>&1 || true
    if [ -x "$HOME/.local/bin/scancode" ]; then
        SCANCODE_CMD="$HOME/.local/bin/scancode"
    fi
fi

if [ -n "$SCANCODE_CMD" ]; then
    log_info "Ejecutando scancode en lib/ ..."
    SCANCODE_OUT="$RESULTS_DIR/phase2_scancode_${TIMESTAMP}.json"
    SCANCODE_MODE="${SCANCODE_MODE:-fast}"
    SCANCODE_TIMEOUT="${SCANCODE_TIMEOUT:-180}"
    SCANCODE_PROCESSES="${SCANCODE_PROCESSES:-8}"

    SCANCODE_ARGS=(
        --json-pp "$SCANCODE_OUT"
        "$ROOT_DIR/lib/"
        --processes "$SCANCODE_PROCESSES"
        --timeout "$SCANCODE_TIMEOUT"
    )

    if [ "$SCANCODE_MODE" = "full" ]; then
        log_info "scancode mode=full (license, package, copyright, info)"
        SCANCODE_ARGS=(
            --license
            --package
            --copyright
            --info
            "${SCANCODE_ARGS[@]}"
        )
    else
        log_info "scancode mode=fast (solo package)"
        SCANCODE_ARGS=(
            --package
            --strip-root
            --ignore "*/test/*"
            --ignore "*/tests/*"
            --ignore "*/examples/*"
            --ignore "*/contrib/*"
            --ignore "*/docs/*"
            --ignore "*/doc/*"
            --ignore "*/benchmark/*"
            "${SCANCODE_ARGS[@]}"
        )
    fi

    set +e
    "$SCANCODE_CMD" "${SCANCODE_ARGS[@]}" 2>&1 | tail -5
    SCANCODE_RC=$?
    set -e

    if [ "$SCANCODE_RC" -eq 0 ]; then
        log_ok "scancode completado → $SCANCODE_OUT"
    elif [ -s "$SCANCODE_OUT" ]; then
        log_warn "scancode devolvió código $SCANCODE_RC pero generó salida JSON utilizable → $SCANCODE_OUT"
    else
        log_error "scancode falló y no generó salida JSON"
    fi
    cp "$SCANCODE_OUT" "$RESULTS_DIR/phase2_scancode_latest.json" 2>/dev/null || true
else
    log_skip "scancode-toolkit no instalado. Instala con: pip install scancode-toolkit"
fi

echo ""
echo "============================================================"
echo "  Fase 2 completada"
echo "  Para calcular métricas: python3 scripts/calculate_metrics.py --phase 2"
echo "============================================================"
