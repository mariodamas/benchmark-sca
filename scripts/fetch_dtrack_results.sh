#!/usr/bin/env bash
# =============================================================================
# fetch_dtrack_results.sh — Descarga los findings de OWASP Dependency-Track
#
# Uso:
#   ./scripts/fetch_dtrack_results.sh <project_name> <project_version>
#   ./scripts/fetch_dtrack_results.sh mi-gateway-iot-benchmark 1.0.0
#
# Prerequisito: haber subido el SBOM con run_phase1.sh
# Output: tests/sca_results/phase1_dtrack_latest.json
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
RESULTS_DIR="$ROOT_DIR/tests/sca_results"

DTRACK_URL="${DTRACK_URL:-http://localhost:8080}"
DTRACK_API_KEY="${DTRACK_API_KEY:-}"
PROJECT_NAME="${1:-mi-gateway-iot-benchmark}"
PROJECT_VERSION="${2:-1.0.0}"

GREEN='\033[0;32m'; RED='\033[0;31m'; BLUE='\033[0;34m'; NC='\033[0m'
log_ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }
log_info()  { echo -e "${BLUE}[INFO]${NC}  $*"; }

if [ -z "$DTRACK_API_KEY" ]; then
    log_error "DTRACK_API_KEY no definido. Ejecuta: export DTRACK_API_KEY=<key>"
    exit 1
fi

mkdir -p "$RESULTS_DIR"

log_info "Buscando proyecto '$PROJECT_NAME' versión '$PROJECT_VERSION' en Dependency-Track..."

# 1. Obtener UUID del proyecto
PROJECTS_JSON=$(curl -s \
    -H "X-Api-Key: $DTRACK_API_KEY" \
    "$DTRACK_URL/api/v1/project?name=$PROJECT_NAME&version=$PROJECT_VERSION")

PROJECT_UUID=$(echo "$PROJECTS_JSON" | python3 -c "
import json, sys
data = json.load(sys.stdin)
projects = data if isinstance(data, list) else [data]
for p in projects:
    if p.get('name') == '$PROJECT_NAME' and p.get('version') == '$PROJECT_VERSION':
        print(p['uuid'])
        break
" 2>/dev/null || echo "")

if [ -z "$PROJECT_UUID" ]; then
    log_error "Proyecto no encontrado en Dependency-Track."
    log_info "Proyectos disponibles:"
    echo "$PROJECTS_JSON" | python3 -c "
import json, sys
data = json.load(sys.stdin)
projects = data if isinstance(data, list) else [data]
for p in projects[:10]:
    print(f\"  - {p.get('name', '?')} v{p.get('version', '?')} [{p.get('uuid', '?')}]\")
" 2>/dev/null || true
    exit 1
fi

log_ok "Proyecto encontrado: UUID=$PROJECT_UUID"

# 2. Descargar findings (vulnerabilidades)
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
FINDINGS_OUT="$RESULTS_DIR/phase1_dtrack_${TIMESTAMP}.json"

log_info "Descargando findings..."
HTTP_CODE=$(curl -s \
    -o "$FINDINGS_OUT" \
    -w "%{http_code}" \
    -H "X-Api-Key: $DTRACK_API_KEY" \
    "$DTRACK_URL/api/v1/finding/project/$PROJECT_UUID")

if [ "$HTTP_CODE" = "200" ]; then
    FINDING_COUNT=$(python3 -c "
import json
with open('$FINDINGS_OUT') as f:
    data = json.load(f)
findings = data if isinstance(data, list) else data.get('findings', [])
print(len(findings))
" 2>/dev/null || echo "?")

    log_ok "Findings descargados: $FINDING_COUNT vulnerabilidades → $FINDINGS_OUT"
    cp "$FINDINGS_OUT" "$RESULTS_DIR/phase1_dtrack_latest.json"
    log_ok "Copiado a phase1_dtrack_latest.json (usado por calculate_metrics.py)"
else
    log_error "Error HTTP $HTTP_CODE al descargar findings"
    cat "$FINDINGS_OUT"
    exit 1
fi
