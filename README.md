# Benchmark SCA para entornos embebidos C/C++

Proyecto de evaluación de herramientas de **Software Composition Analysis (SCA)** sobre un proyecto sintético que simula un gateway IoT con librerías de terceros en versiones deliberadamente vulnerables.

> **ADVERTENCIA:** Este repositorio contiene versiones de librerías con vulnerabilidades conocidas. **No usar en producción.** Su único propósito es el benchmarking de herramientas SCA.

---

## Contexto

Este benchmark forma parte de un Trabajo de Fin de Grado (TFG) cuyo objetivo es evaluar qué herramientas de SCA resultan más adecuadas para integrarse en un pipeline de seguridad para proyectos C/C++ embebidos. La evaluación cubre los tres escenarios habituales de inclusión de componentes de terceros (TPL):

1. **SBOM** — inventario de dependencias en formato estándar (CycloneDX 1.4)
2. **Vendoring** — código fuente de terceros incorporado directamente al repositorio
3. **Binario** — artefacto ELF compilado sin información de dependencias a nivel manifiesto

---

## Estructura del repositorio

```
benchmark-sca/
├── CMakeLists.txt                  ← Build del binario de benchmark
├── vcpkg.json.in                   ← Plantilla de dependencias declaradas (Fase 1)
├── main.c                          ← Punto de entrada del binario sintético
├── .syft.yaml                      ← Configuración de Syft para generación de SBOM
├── corpus_b/
│   └── mosquitto_sbom.json         ← SBOM de Mosquitto v2.0.18 (validación ecológica)
├── scripts/
│   ├── setup.sh                    ← Descarga librerías vulnerables y compila el binario
│   ├── gen_sbom_from_vcpkg.py      ← Genera SBOM CycloneDX desde vcpkg.json
│   ├── run_all_phases.sh           ← Ejecuta las tres fases del benchmark
│   ├── run_phase1_simple.sh        ← Fase 1: Grype, Trivy, Snyk sobre SBOM
│   ├── run_phase2.sh               ← Fase 2: Snyk --unmanaged, OWASP DC sobre lib/
│   ├── run_phase3.sh               ← Fase 3: CVE-Binary-Tool, Grype, Trivy sobre binario
│   ├── run_phase3_emba.sh          ← Fase 3 (profundo): EMBA firmware analysis
│   ├── run_snyk_contiki.sh         ← Validación Corpus B: Contiki-NG v4.9
│   ├── fetch_dtrack_results.sh     ← Obtiene resultados de Dependency-Track via API
│   └── compute_all_metrics.py      ← Calcula TP/FP/FN/F1 para todas las fases
└── docs/
    ├── BENCHMARK_METHODOLOGY.md    ← Diseño experimental y metodología completa
    ├── BENCHMARK_HIBRIDO_FINAL.md  ← Resultados detallados con análisis por herramienta
    ├── ground_truth.csv            ← 196 CVEs verificados (ground truth canónico)
    ├── ground_truth_phase3_effective.csv ← 37 CVEs alcanzables por análisis binario
    ├── metrics_final.json          ← Métricas calculadas (ejecución final)
    └── tool_execution_times.json   ← Tiempos de ejecución medidos
```

---

## Ground Truth

**196 CVEs** verificados contra NVD API v2 (2026-04-07) sobre nueve componentes:

| Librería | Versión   | CVEs GT | Tipo de inclusión    | Fases   |
|----------|-----------|--------:|----------------------|---------|
| curl     | 7.58.0    |      49 | declarada (vcpkg)    | 1, 3    |
| OpenSSL  | 1.0.2k    |      39 | declarada (vcpkg)    | 1, 3    |
| mbedTLS  | 2.16.0    |      35 | precompilada (.a/.so)| 3       |
| wolfSSL  | 4.3.0     |      24 | precompilada (.a/.so)| 3       |
| expat    | 2.4.6     |      18 | fuente (lib/)        | 1, 2, 3 |
| libpng   | 1.6.34    |      13 | fuente (lib/)        | 1, 2, 3 |
| lwIP     | 2.1.2     |       8 | fuente (lib/)        | 2, 3    |
| SQLite   | 3.39.1    |       6 | amalgamación (lib/)  | 1, 2, 3 |
| zlib     | 1.2.11    |       4 | fuente (lib/)        | 1, 2, 3 |

**GT por fase:** Fase 1 = 129 CVEs · Fase 2 = 49 CVEs · Fase 3 = 196 CVEs (37 efectivos)

---

## Resultados

### Fase 1 — SBOM (GT = 129 CVEs)

| Herramienta            | TP  | FP | FN  | Precisión | Recall | F1        | Tiempo |
|------------------------|-----|----|-----|----------:|-------:|-----------|-------:|
| Grype v0.109           | 120 |  9 |   9 |    93,0 % | 93,0 % | **0,930** |   22 s |
| Dependency-Track v4.11 | 102 |  1 |  27 |    99,0 % | 79,1 % | **0,879** |  ~12 s |
| Trivy v0.69            |   0 |  0 | 129 |       N/D |  0,0 % | 0,000     |    1 s |
| Snyk v1.x              |   0 |  0 | 129 |       N/D |  0,0 % | 0,000     |   11 s |

**Selección:** Grype (F1=0,930) para CI/CD. Dependency-Track como plataforma complementaria de monitorización continua.

### Fase 2 — Vendoring (GT = 49 CVEs)

| Herramienta            | TP | FP | FN | Precisión | Recall | F1        | Tiempo  |
|------------------------|----|----|----|----------:|-------:|-----------|--------:|
| Snyk --unmanaged       | 39 |  8 | 10 |    83,0 % | 79,6 % | **0,812** |    40 s |
| OWASP DC v11.1.1       |  6 | 22 | 43 |    21,4 % | 12,2 % | 0,156     | 4 s (*) |

(*) Con base de datos cacheada (`--noupdate`). Primera ejecución con descarga NVD: ~25 min.

**Selección:** Snyk --unmanaged (F1=0,812). OWASP DC descartado por tasa de FP del 78%.

### Fase 3 — Binario (GT efectivo = 37 CVEs)

| Herramienta            | TP | FP | FN  | Precisión | Recall | F1        | Tiempo     |
|------------------------|----|----|-----|----------:|-------:|-----------|------------|
| EMBA v2.0.0            | 23 | 13 |   3 |    63,9 % | 88,5 % | **0,743** | 10.241 s   |
| CVE-Binary-Tool v3.4   | 16 |  3 |  21 |    84,2 % | 43,2 % | **0,571** | 10 s       |
| Grype (binario)        |  0 |  0 |  37 |       N/D |  0,0 % | 0,000     | 9 s        |
| Trivy (binario)        |  0 |  0 |  37 |       N/D |  0,0 % | 0,000     | <1 s       |

**Selección:** EMBA (análisis profundo, nightly) + CVE-Binary-Tool (gate rápido en CI/CD).

> El GT efectivo de Fase 3 (37 CVEs) excluye los 59 CVEs de mbedTLS y wolfSSL que son estructuralmente indetectables por string-matching de versión semántica en el ELF.

### Cobertura acumulada del pipeline completo

| Fase | Herramienta seleccionada  | TPs acumulados (deduplicados) |
|------|---------------------------|------------------------------:|
| Fase 1 | Grype v0.109            | 120                           |
| Fase 2 | Snyk --unmanaged        | +9 nuevos → 129               |
| Fase 3 | CVE-Binary-Tool v3.4    | +3 nuevos → 132               |
| **Pipeline total** |            | **≥132 / 196 (~67 %)** |

Excluyendo los 59 CVEs estructuralmente indetectables (mbedTLS + wolfSSL): **≥132 / 137 ≈ 96 %**.

---

## Ejecución

### Requisitos

- Linux / WSL2 Ubuntu 22.04+
- Python 3.10+, Java 11+ (OWASP DC), Docker (EMBA)
- Herramientas: `grype`, `syft`, `trivy`, `cve-bin-tool`, `snyk`
- Variables de entorno: `SNYK_TOKEN`, `DTRACK_API_KEY`, `DTRACK_URL`

```bash
# Configurar credenciales (sin hardcodear tokens)
cat > .env.local <<'EOF'
SNYK_TOKEN=<tu_token>
DTRACK_API_KEY=<tu_api_key>
DTRACK_URL=https://<tu-dtrack>
EOF
```

### Setup del entorno

```bash
# Descargar librerías vulnerables y compilar el binario ELF
bash scripts/setup.sh

# Generar SBOM CycloneDX con CPEs explícitos para Fase 1
python3 scripts/gen_sbom_from_vcpkg.py
```

### Benchmark completo (las tres fases)

```bash
bash scripts/run_all_phases.sh
python3 scripts/compute_all_metrics.py
```

### Ejecución por fase

```bash
bash scripts/run_phase1_simple.sh    # Fase 1: SBOM
bash scripts/run_phase2.sh           # Fase 2: Vendoring
bash scripts/run_phase3.sh           # Fase 3: Binario (CBT + Grype + Trivy)
bash scripts/run_phase3_emba.sh      # Fase 3: Firmware profundo (EMBA)
```

> Si el entorno de ejecución no dispone de WSL2 o Docker, el repositorio incluye los resultados finales en `docs/` y `docs/metrics_final.json` para validación documental sin necesidad de re-ejecutar.

---

## Documentación

| Documento | Descripción |
|-----------|-------------|
| [docs/BENCHMARK_METHODOLOGY.md](docs/BENCHMARK_METHODOLOGY.md) | Diseño experimental, métricas y consideraciones metodológicas |
| [docs/BENCHMARK_HIBRIDO_FINAL.md](docs/BENCHMARK_HIBRIDO_FINAL.md) | Resultados detallados con análisis por herramienta y fase |
| [RESULTS.md](RESULTS.md) | Resumen ejecutivo de resultados para referencia rápida |
| [docs/ground_truth.csv](docs/ground_truth.csv) | Ground truth completo (196 CVEs verificados) |
| [docs/metrics_final.json](docs/metrics_final.json) | Métricas en formato estructurado |

---

## Licencia

MIT — Solo para benchmarking y evaluación de herramientas SCA. No apto para uso en producción.
