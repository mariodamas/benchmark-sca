#!/bin/bash
# Script: Run Snyk --unmanaged on Contiki-NG v4.9
# Purpose: Validate Phase 2 detection on ecological corpus (real-world project)
# Ground truth: tinyDTLS in Contiki-NG has 8 known CVEs
# 
# PREREQUISITE: snyk auth must be run first to obtain token
#   Run: snyk auth
#

echo "=== Snyk --unmanaged on Contiki-NG v4.9 (Phase 2) ==="
echo ""
echo "Ground truth CVEs in Contiki-NG (tinyDTLS):"
echo "  CVE-2021-34430"
echo "  CVE-2021-42141"
echo "  CVE-2021-42142"
echo "  CVE-2021-42143"
echo "  CVE-2021-42144"
echo "  CVE-2021-42145"
echo "  CVE-2021-42146"
echo "  CVE-2021-42147"
echo ""

cd corpus_b/contiki-ng || { echo "Error: corpus_b/contiki-ng directory not found"; exit 1; }

echo "Executing: snyk test --unmanaged --json"
snyk test --unmanaged --json > ../../tests/sca_results/snyk_contiki_fase2.json

exit_code=$?

if [ $exit_code -eq 0 ]; then
    echo "✓ Results saved to: tests/sca_results/snyk_contiki_fase2.json"
    echo ""
    echo "To analyze results:"
    echo "  python scripts/calculate_metrics.py --file tests/sca_results/snyk_contiki_fase2.json --groundtruth docs/ground_truth.csv --tool snyk_contiki"
else
    echo "✗ Snyk failed with exit code $exit_code"
    echo ""
    echo "Common fixes:"
    echo "  1. Verify token: snyk auth"
    echo "  2. Check organization: snyk config get api"
    echo "  3. Login again: snyk auth --force"
fi

exit $exit_code
