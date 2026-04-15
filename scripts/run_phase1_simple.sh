#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJ="$(dirname "$SCRIPT_DIR")"
RES="$PROJ/tests/sca_results"
SBOM="$PROJ/sbom/sbom-cyclonedx.json"

if [ -f "$PROJ/.env.local" ]; then
    # shellcheck disable=SC1091
    set -a
    source "$PROJ/.env.local"
    set +a
fi

mkdir -p "$RES"

echo "=== FASE 1 ==="
echo "SBOM: $SBOM"

# Grype
echo -n "[Grype] "
T0=$SECONDS
if command -v grype >/dev/null 2>&1 && [ -f "$SBOM" ]; then
    grype "sbom:$SBOM" -o json --file "$RES/phase1_grype_latest.json" 2>/dev/null || true
else
    echo "skip (grype no instalado o SBOM inexistente)"
fi
echo "$(( SECONDS - T0 ))s done"

# Trivy
echo -n "[Trivy] "
T0=$SECONDS
if command -v trivy >/dev/null 2>&1 && [ -f "$SBOM" ]; then
    trivy sbom "$SBOM" --format json --output "$RES/trivy_fase1_sbom.json" --quiet 2>/dev/null || true
else
    echo "skip (trivy no instalado o SBOM inexistente)"
fi
echo "$(( SECONDS - T0 ))s done"

# Snyk vcpkg
echo -n "[Snyk vcpkg] "
T0=$SECONDS
if command -v snyk >/dev/null 2>&1 && [ -n "${SNYK_TOKEN:-}" ] && [ -f "$PROJ/vcpkg.json" ]; then
    snyk test --json --file="$PROJ/vcpkg.json" --package-manager=vcpkg \
        > "$RES/phase1_snyk_latest.json" 2>/dev/null || true
else
    echo "skip (snyk no instalado, SNYK_TOKEN ausente o vcpkg.json inexistente)"
fi
echo "$(( SECONDS - T0 ))s done"

echo "=== Contando resultados ==="
python3 "$PROJ/scripts/compute_all_metrics.py" 2>&1
