# mi-gateway-iot — Benchmark SCA para entornos embebidos C/C++

Proyecto sintético para evaluar herramientas de **Software Composition Analysis (SCA)**
en proyectos C/C++ embebidos. Simula un gateway IoT con librerías de terceros en
versiones deliberadamente vulnerables.

> ⚠️ **ADVERTENCIA**: Contiene versiones de librerías con vulnerabilidades conocidas.
> **NO usar en producción.** Exclusivamente para benchmarking de herramientas SCA.

> ✅ **ACTUALIZACIÓN 2026-04-16**: Análisis de firmware con EMBA v2.0.0 completado exitosamente.
> Ver sección Fase 3 y [docs/BENCHMARK_HIBRIDO_FINAL.md](docs/BENCHMARK_HIBRIDO_FINAL.md#322-emba-v200--análisis-de-firmware-embebido-ejecutado) para resultados detallados.

---

## Estructura

```
mi-gateway-iot/
├── CMakeLists.txt              ← build del binario benchmark
├── vcpkg.json                  ← dependencias declaradas (Fase 1)
├── main.c
├── lib/                        ← librerías vulnerables vendored (Fase 2 y 3)
│   ├── zlib-1.2.11/
│   ├── libpng-1.6.34/
│   ├── lwip-2.1.2/
│   ├── expat-2.4.6/
│   └── sqlite-3.39.1/
├── build/
│   └── mi-gateway              ← binario ELF compilado (Fase 3)
├── sbom/
│   └── sbom-cyclonedx.json     ← SBOM con los 6 componentes declarados
├── scripts/
│   ├── setup.sh                ← descarga librerías + compila binario
│   ├── gen_sbom_from_vcpkg.py  ← genera SBOM CycloneDX desde vcpkg.json
│   ├── run_all_phases.sh       ← ejecuta las 3 fases completas
│   ├── run_phase1_simple.sh    ← Fase 1: Grype, Trivy, Snyk sobre SBOM
│   ├── run_phase2.sh           ← Fase 2: Snyk --unmanaged, OWASP DC
│   ├── run_phase3.sh           ← Fase 3: CBT, Grype, Trivy sobre binario
│   ├── run_snyk_contiki.sh     ← Validación Corpus B: Contiki-NG v4.9
│   ├── fetch_dtrack_results.sh ← Obtiene resultados de Dependency-Track API
│   └── compute_all_metrics.py  ← calcula TP/FP/FN/F1 para todas las fases
├── tests/sca_results/          ← JSONs de salida (_latest = ejecución actual)
└── docs/
    ├── BENCHMARK_HIBRIDO_FINAL.md        ← resultados completos con EMBA + análisis
    ├── BENCHMARK_METHODOLOGY.md          ← diseño experimental y metodología
    ├── ground_truth.csv                  ← 196 CVEs verificados (GT canónico)
    ├── ground_truth_phase3_effective.csv ← 37 CVEs alcanzables por análisis binario (Fase 3)
    ├── metrics_final.json                ← métricas calculadas (última ejecución)
    └── tool_execution_times.json         ← tiempos de ejecución medidos
```

---

## Ground Truth

**196 CVEs** verificados contra NVD API v2 (2026-04-07):

| Librería | Versión | CVEs GT | Tipo | Fases |
|----------|---------|--------:|------|-------|
| curl | 7.58.0 | 49 | declarada (vcpkg) | 1, 3 |
| OpenSSL | 1.0.2k | 39 | declarada (vcpkg) | 1, 3 |
| mbedTLS | 2.16.0 | 35 | precompilada (.a/.so) | 3 |
| wolfSSL | 4.3.0 | 24 | precompilada (.a/.so) | 3 |
| expat | 2.4.6 | 18 | fuente (lib/) | 1, 2, 3 |
| libpng | 1.6.34 | 13 | fuente (lib/) | 1, 2, 3 |
| lwIP | 2.1.2 | 8 | fuente (lib/) | 2, 3 |
| SQLite | 3.39.1 | 6 | amalgamación (lib/) | 1, 2, 3 |
| zlib | 1.2.11 | 4 | fuente (lib/) | 1, 2, 3 |

**GT Fase 3 efectivo:** 37 CVEs (librerías con versión semántica embebida en binario: expat, libpng, SQLite, zlib).

---

## Resultados (ejecución 2026-04-07/08)

### Fase 1 — SBOM (GT=129 CVEs)

| Herramienta | TP | FP | FN | F1 | Tiempo |
|-------------|----|----|-----|-----|-------:|
| Grype v0.109 | 120 | 9 | 9 | **0.930** | 22 s |
| Dependency-Track v4.11 | 102 | 1 | 27 | **0.879** | ~12 s |
| Trivy v0.69 | 0 | 0 | 129 | 0.000 | 1 s |
| Snyk v1.x | 0 | 0 | 129 | 0.000 | 11 s |

### Fase 2 — Vendoring (GT=49 CVEs)

| Herramienta | TP | FP | FN | F1 | Tiempo |
|-------------|----|----|-----|-----|-------:|
| Snyk --unmanaged | 39 | 8 | 10 | **0.812** | 40 s |
| OWASP DC v11.1.1 | 6 | 22 | 43 | 0.156 | 4 s* |

*Con DB cacheada. Primera ejecución: ~25 min (descarga NVD).

### Fase 3 — Binario (GT=196 / GT_eff=37)

| Herramienta | TP | FP | FN | F1 (GT) | F1 (GT_eff) | Tiempo |
|-------------|----|----|-----|---------|------------|-------:|
| EMBA v2.0.0 | 23 | 13 | 3 | 0.599 | **0.743** | 10,241 s |
| CVE-Binary-Tool v3.4 | 16 | 3 | 21 | 0.167 | **0.571** | 10 s |
| Grype (binary) | 0 | 0 | 196 | 0.000 | — | 9 s |
| Trivy (binary) | 0 | 0 | 196 | 0.000 | — | <1 s |

Ver [docs/BENCHMARK_HIBRIDO_FINAL.md](docs/BENCHMARK_HIBRIDO_FINAL.md) para análisis completo.

---

## Ejecución rápida

### Requisitos

- WSL2 Ubuntu 22.04+ con `grype`, `syft`, `trivy`, `cve-bin-tool`, `snyk` instalados
- Python 3.10+, Java 11+ (para OWASP DC)
- Variables de entorno: `SNYK_TOKEN`, `DTRACK_API_KEY`, `DTRACK_URL`

Si no tienes permisos de administrador en Windows, no podras instalar WSL2 o Docker Desktop localmente.
En ese caso, ejecuta este benchmark en una maquina Linux/WSL ya preparada o en CI/CD.
El repositorio ya incluye resultados finales en `docs/` para validacion documental.

Credenciales locales recomendadas (sin hardcodear tokens):

```bash
cat > .env.local <<'EOF'
SNYK_TOKEN=tu_token
DTRACK_API_KEY=tu_api_key
DTRACK_URL=https://tu-dtrack
EOF
```

### Setup inicial

```bash
# Descargar librerías vulnerables y compilar binario
bash scripts/setup.sh

# Generar SBOM correcto para Fase 1
python3 scripts/gen_sbom_from_vcpkg.py
```

### Ejecutar benchmark completo

```bash
# Las 3 fases
bash scripts/run_all_phases.sh

# Calcular métricas
python3 scripts/compute_all_metrics.py
```

### EMBA (Fase 3B — Firmware Analysis)

✅ **EMBA v2.0.0 ejecutado exitosamente** (2026-04-16)

EMBA (Embedded Linux Analyzer) realiza análisis comprehensivo de firmware con detección CVE via F17 CVE-bin-tool module.

**Resultados Phase 3 con EMBA:**
- CVEs detectados: 36 (16 expat + 6 zlib + 4 sqlite + 10 libpng)
- Precision: 63.9% | Recall: 88.5% | **F1: 0.743**
- Tiempo: 10,241 s (~2h50m)
- Artefactos: 60+ módulos análisis, SBOM CycloneDX, weak functions, protecciones binarias

**Ejecución manual:**
```bash
bash scripts/run_phase3_emba.sh --binary build/mi-gateway --results-dir tests/sca_results
```

**Resultados generados en:**
- `tests/sca_results/phase3_emba_latest.json` (status + metadatos)
- `tests/sca_results/emba_out_*/` (reportes completos)

Ver [docs/BENCHMARK_HIBRIDO_FINAL.md § 3.2.3](docs/BENCHMARK_HIBRIDO_FINAL.md#322-emba-v200--análisis-de-firmware-embebido-ejecutado) para análisis detallado.

### Ejecutar fase individual

```bash
bash scripts/run_phase1_simple.sh   # Fase 1: SBOM
bash scripts/run_phase2.sh          # Fase 2: Vendoring
bash scripts/run_phase3.sh          # Fase 3: Binario (CBT + Grype + Trivy)
bash scripts/run_phase3_emba.sh     # Fase 3B: Firmware (EMBA)
```

---

## Licencia

MIT — Solo para benchmarking y evaluación de herramientas SCA.
