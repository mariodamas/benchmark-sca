# Metodologia del Benchmark SCA Hibrido — mi-gateway-iot

## 1. Objetivo

Evaluar capacidad de deteccion de CVEs en C/C++ embebido en tres planos tecnicos:

1. SBOM
2. Codigo fuente vendoreado
3. Binario ELF

El benchmark mide precision, recall y F1 por fase y por herramienta.

---

## 2. Alcance y version metodologica

Este documento describe la **version hibrida final** del benchmark.

- Ground truth de referencia: 166 CVEs (dataset canónico actual).
- Conjuntos de evaluacion por fase usados en resultados finales:
  - Fase 1: GT=100
  - Fase 2: GT=30
  - Fase 3: GT=166

Importante: estos GT por fase son universos de evaluacion diferentes.
No deben sumarse para inferir una cobertura global unica sin deduplicacion.

Nota metodológica: la revisión de FP de Snyk para Fase 2 se conserva como análisis
complementario en `tests/sca_results/snyk_fp_analysis.json`.

---

## 3. Diseño experimental

### 3.1 Corpus

- Corpus A: proyecto sintetico mi-gateway-iot.
- Corpus B: validacion ecologica con proyectos reales:
  - Mosquitto v2.0.18 para fase 1.
  - Contiki-NG v4.9 para fase 2.

### 3.2 Tipos de inclusion de TPL

| Tipo de inclusion | Ejemplo | Fases |
|---|---|---|
| Declarada | curl, OpenSSL | 1 y 3 |
| Copiada (vendoring) | zlib, libpng, lwIP, expat | 2 y 3 |
| Amalgamation | SQLite | 2 y 3 |

---

## 4. Herramientas evaluadas

La evaluacion incluye herramientas candidatas del ecosistema OSS y comercial/freemium.

### 4.1 Fase 1 (SBOM)

- Grype
- Trivy
- Snyk
- Dependency-Track (comparacion exploratoria adicional)

### 4.2 Fase 2 (codigo vendoreado)

- Snyk --unmanaged
- FOSSA
- ORT
- ScanCode

### 4.3 Fase 3 (binario)

- CVE-Binary-Tool
- Grype (binario)
- Trivy (binario)

---

## 5. Metricas

- Precision = TP / (TP + FP)
- Recall = TP / (TP + FN)
- F1 = 2 * (Precision * Recall) / (Precision + Recall)

Definiciones:

- TP: CVE detectado y presente en el GT de la fase.
- FP: CVE detectado pero ausente del GT de la fase.
- FN: CVE presente en el GT de la fase y no detectado.

Regla de reporte:

1. Se reportan metricas por fase.
2. No se reporta porcentaje global unico del pipeline si no existe union deduplicada de TP sobre GT unico.

---

## 6. Consideraciones metodologicas criticas

### 6.1 Trivy: distinguir SBOM vs fuentes

- En fase 1 (SBOM), Trivy evalua el SBOM de entrada. Un resultado nulo debe discutirse en terminos
  de calidad/mapeo del SBOM y cobertura de la herramienta para ese input.
- En escenarios de fuentes (ejemplo Mosquitto con syft dir), el problema principal es el input SBOM
  incompleto por no resolucion de dependencias de sistema via CMake.

### 6.2 Dependency-Track en el marco del TFG

- Se mantiene como comparacion exploratoria adicional en fase 1.
- No redefine el candidate set central de la PoC para la decision operativa por commit.
- La monitorizacion continua se trata como capacidad operativa separada y fuera del benchmark.

---

## 7. Procedimiento resumido de ejecucion

1. Generar SBOM del objetivo evaluado.
2. Ejecutar herramientas por fase.
3. Calcular TP/FP/FN por fase sobre su GT correspondiente.
4. Reportar resultados por fase y validacion ecologica en Corpus B.

---

## 8. Limitaciones

1. Syft dir puede producir SBOM incompleto en proyectos CMake con dependencias de sistema.
2. Fase 3 sufre FN estructurales en librerias sin version semantica visible en binario.
3. Fase 2 requiere triaje manual por FP residuales en Snyk --unmanaged.

---

## 9. Referencias

- NVD: https://nvd.nist.gov
- Syft: https://github.com/anchore/syft
- Grype: https://github.com/anchore/grype
- CVE-Binary-Tool: https://github.com/intel/cve-bin-tool
- Dependency-Track: https://dependencytrack.org
