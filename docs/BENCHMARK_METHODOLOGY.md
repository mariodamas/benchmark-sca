# Metodología del Benchmark SCA Híbrido

## 1. Objetivo

Evaluar la capacidad de detección de CVEs en proyectos C/C++ embebidos mediante tres técnicas complementarias:

1. Análisis de inventario SBOM (Software Bill of Materials)
2. Análisis de código fuente incorporado como vendoring
3. Análisis de artefactos binarios (ELF)

El benchmark mide precisión, recall y F1 por fase y por herramienta, sobre un corpus sintético con ground truth verificado contra la NVD API v2.

---

## 2. Ground Truth

**196 CVEs** verificados contra NVD API v2 (fecha de corte: 2026-04-07) sobre nueve componentes en versiones deliberadamente vulnerables:

| Librería    | Versión | CVEs GT | CRIT | HIGH | MED | LOW | Tipo de inclusión | Fases |
|-------------|---------|--------:|-----:|-----:|----:|----:|-------------------|-------|
| curl        | 7.58.0  |      49 |    0 |   14 |  30 |   5 | declarada (vcpkg) | 1, 3  |
| OpenSSL     | 1.0.2k  |      39 |    1 |   14 |  22 |   2 | declarada (vcpkg) | 1, 3  |
| mbedTLS     | 2.16.0  |      35 |    4 |   14 |  17 |   0 | precompilada      | 3     |
| wolfSSL     | 4.3.0   |      24 |    4 |    8 |  12 |   0 | precompilada      | 3     |
| expat       | 2.4.6   |      18 |    2 |    9 |   4 |   3 | fuente (lib/)     | 1,2,3 |
| libpng      | 1.6.34  |      13 |    0 |    5 |   7 |   0 | fuente (lib/)     | 1,2,3 |
| lwIP        | 2.1.2   |       8 |    2 |    6 |   0 |   0 | fuente (lib/)     | 2, 3  |
| SQLite      | 3.39.1  |       6 |    0 |    3 |   3 |   0 | amalgamación      | 1,2,3 |
| zlib        | 1.2.11  |       4 |    2 |    2 |   0 |   0 | fuente (lib/)     | 1,2,3 |
| **Total**   |         | **196** |   15 |   75 |  95 |  10 |                   |       |

**GT por fase:**

| Fase | Universo de evaluación | CVEs GT |
|------|------------------------|--------:|
| Fase 1 (SBOM) | curl, OpenSSL, expat, libpng, SQLite, zlib declarados en vcpkg | 129 |
| Fase 2 (Vendoring) | expat, libpng, lwIP, SQLite, zlib en lib/ | 49 |
| Fase 3 (Binario, GT completo) | todos los componentes | 196 |
| Fase 3 (Binario, GT efectivo) | librerías con versión semántica embebida en ELF | 37 |

> Los universos de evaluación son diferentes por fase y no deben sumarse directamente para inferir cobertura global sin deduplicación.

### Evolución del GT (cambios respecto al conjunto original de 178 CVEs)

- **Eliminados (4):** CVE-2009-1390/3765/3766/3767 — asignados erróneamente a OpenSSL; son vulnerabilidades en aplicaciones que usan OpenSSL (Mutt, OpenLDAP), no en la librería.
- **Añadidos (22):** GT_GAPs confirmados via NVD — CVEs reales en el rango de versión afectado, detectados por herramientas pero ausentes del GT original.

---

## 3. Diseño experimental

### 3.1 Corpus

- **Corpus A:** proyecto sintético `mi-gateway-iot` — gateway IoT embebido con nueve librerías de terceros en versiones deliberadamente vulnerables.
- **Corpus B:** validación ecológica con proyectos reales:
  - Mosquitto v2.0.18 (Fase 1)
  - Contiki-NG v4.9 (Fase 2)

### 3.2 Tipos de inclusión de componentes de terceros (TPL)

| Tipo | Ejemplo | Características | Fases evaluadas |
|------|---------|-----------------|-----------------|
| Declarada (manifiesto) | curl, OpenSSL | Declarada en vcpkg.json con CPE y PURL | 1, 3 |
| Vendoring (código fuente) | zlib, libpng, lwIP, expat | Copiada directamente en lib/ | 2, 3 |
| Amalgamación | SQLite | Fichero único generado (sqlite3.c) | 1, 2, 3 |
| Precompilada (.a/.so) | mbedTLS, wolfSSL | Biblioteca sin fuentes en el repo | 3 |

---

## 4. Herramientas evaluadas

### 4.1 Fase 1 — Análisis SBOM

| Herramienta | Versión | Tipo | Resultado |
|-------------|---------|------|-----------|
| Grype | 0.109 | OSS | F1=0.930 — **seleccionada** |
| Dependency-Track | 4.11 | OSS (servidor) | F1=0.879 — complementaria |
| Trivy | 0.69 | OSS | F1=0.000 — descartada |
| Snyk | 1.x | Comercial | F1=0.000 — no aplica Phase 1 |

### 4.2 Fase 2 — Código fuente vendorizado

| Herramienta | Versión | Tipo | Resultado |
|-------------|---------|------|-----------|
| Snyk --unmanaged | 1.x | Comercial | F1=0.812 — **seleccionada** |
| OWASP Dependency-Check | 11.1.1 | OSS | F1=0.156 — descartada |
| FOSSA / ORT / ScanCode | — | OSS | F1=0.000 — no aplican |

### 4.3 Fase 3 — Análisis binario

| Herramienta | Versión | Tipo | Resultado (GT efectivo) |
|-------------|---------|------|------------------------|
| EMBA | 2.0.0 | OSS | F1=0.743 — **seleccionada (profundo)** |
| CVE-Binary-Tool | 3.4 | OSS | F1=0.571 — **seleccionada (rápido)** |
| Grype (binary) | 0.109 | OSS | F1=0.000 — descartada |
| Trivy (binary) | 0.69 | OSS | F1=0.000 — descartada |

---

## 5. Métricas

```
Precision = TP / (TP + FP)
Recall    = TP / (TP + FN)
F1        = 2 · (Precision · Recall) / (Precision + Recall)
```

**Definiciones:**
- **TP:** CVE detectado por la herramienta y presente en el GT de la fase.
- **FP:** CVE detectado por la herramienta pero ausente del GT de la fase (verificado contra NVD).
- **FN:** CVE presente en el GT de la fase y no detectado por la herramienta.

**Reglas de reporte:**
1. Las métricas se reportan por fase y por herramienta.
2. La cobertura global del pipeline se calcula sobre la unión deduplicada de TPs sobre el GT único de 196 CVEs.
3. Se distinguen FN estructurales (imposibles de detectar con la técnica evaluada) de FN por cobertura de base de datos.

---

## 6. Consideraciones metodológicas

### 6.1 GT efectivo para Fase 3

El GT completo de 196 CVEs incluye librerías (mbedTLS, wolfSSL) cuyos binarios precompilados no contienen la versión semántica como string en el ELF. Esto hace que 59 CVEs sean **estructuralmente indetectables** por técnicas de string-matching de versión. El GT efectivo de Fase 3 (37 CVEs) restringe la evaluación a las librerías para las que las herramientas binarias tienen capacidad técnica real: expat, libpng, SQLite y zlib.

### 6.2 Trivy — distinción SBOM vs. imagen Docker

Trivy no detecta vulnerabilidades en SBOMs CycloneDX con componentes C/C++ nativos definidos solo por CPE/PURL genérico. Su ecosistema objetivo son imágenes de contenedor y paquetes de sistema operativo. El resultado F1=0.000 en Fase 1 está acotado al artefacto de entrada (SBOM CycloneDX de fuentes C/C++) y no debe generalizarse como limitación absoluta de la herramienta.

### 6.3 Snyk — limitación en ecosistema vcpkg (Fase 1)

Snyk no tiene soporte para `vcpkg` como gestor de paquetes C/C++ en su modo de análisis de manifiestos. El resultado F1=0.000 en Fase 1 es una limitación del ecosistema. La herramienta sí ofrece capacidad real en Fase 2 mediante el modo `--unmanaged`.

### 6.4 Dependency-Track — monitorización continua

Se mantiene como comparación exploratoria adicional en Fase 1. Su caso de uso principal es la monitorización continua de un SBOM persistente, no la integración en CI/CD por commit.

### 6.5 Syft — generación de SBOM

`syft dir:` sobre fuentes C/C++ con CMake no resuelve dependencias declaradas via `find_package()`. Para un SBOM útil en proyectos CMake con dependencias del sistema, el método correcto es `syft image:` sobre la imagen Docker final o `syft dir:` sobre el directorio de instalación.

---

## 7. Procedimiento de ejecución

```
1. Generar SBOM del objetivo:       python3 scripts/gen_sbom_from_vcpkg.py
2. Fase 1 (SBOM):                   bash scripts/run_phase1_simple.sh
3. Fase 2 (Vendoring):              bash scripts/run_phase2.sh
4. Fase 3 (Binario rápido):         bash scripts/run_phase3.sh
5. Fase 3 (Firmware profundo):      bash scripts/run_phase3_emba.sh
6. Calcular métricas:               python3 scripts/compute_all_metrics.py
```

O, alternativamente, mediante el script unificado:

```bash
bash scripts/run_all_phases.sh
python3 scripts/compute_all_metrics.py
```

---

## 8. Limitaciones identificadas

1. **Syft `dir:` incompleto sobre CMake:** No resuelve `find_package()`. Mitigación: usar `syft image:`.
2. **FN estructurales en Fase 3:** mbedTLS (35 CVEs) y wolfSSL (24 CVEs) sin versión semántica embebida en ELF.
3. **Snyk --unmanaged requiere API cloud:** Incompatible con entornos aislados sin conectividad externa.
4. **OWASP DC tasa de FP elevada:** 78% FP por falsos matches de nombre de archivo en código C/C++ embebido.
5. **lwIP FN estructural en Fase 2:** La base de firmas de Snyk --unmanaged no cubre lwIP.
6. **EMBA coste temporal:** ~2h50m por ejecución, no embebible como gate bloqueante en CI/CD.

---

## 9. Referencias

- NVD API v2: https://nvd.nist.gov/developers/vulnerabilities
- Syft: https://github.com/anchore/syft
- Grype: https://github.com/anchore/grype
- Trivy: https://github.com/aquasecurity/trivy
- EMBA: https://github.com/e-m-b-a/emba
- CVE-Binary-Tool: https://github.com/intel/cve-bin-tool
- Dependency-Track: https://dependencytrack.org
- OWASP Dependency-Check: https://jeremylong.github.io/DependencyCheck
- Snyk: https://docs.snyk.io/snyk-cli/commands/test
