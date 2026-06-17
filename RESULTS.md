# Resultados del Benchmark SCA — Resumen Ejecutivo

**Proyecto:** Benchmark SCA para entornos embebidos C/C++ (`mi-gateway-iot`)  
**Fecha de ejecución:** 2026-04-07 / 2026-04-16 (EMBA)  
**Entorno:** WSL2 Ubuntu 22.04 · AMD Ryzen 7 · 16 GB RAM · SSD NVMe  
**Ground truth:** 196 CVEs verificados contra NVD API v2

---

## Ground Truth

El corpus sintético contiene nueve librerías de terceros en versiones deliberadamente vulnerables, cubriendo los tres escenarios de inclusión habituales en C/C++ embebido:

| Librería | Versión | CVEs GT | CRIT | HIGH | MED | LOW | Tipo            |
|----------|---------|--------:|-----:|-----:|----:|----:|-----------------|
| curl     | 7.58.0  |      49 |    0 |   14 |  30 |   5 | declarada       |
| OpenSSL  | 1.0.2k  |      39 |    1 |   14 |  22 |   2 | declarada       |
| mbedTLS  | 2.16.0  |      35 |    4 |   14 |  17 |   0 | precompilada    |
| wolfSSL  | 4.3.0   |      24 |    4 |    8 |  12 |   0 | precompilada    |
| expat    | 2.4.6   |      18 |    2 |    9 |   4 |   3 | fuente (lib/)   |
| libpng   | 1.6.34  |      13 |    0 |    5 |   7 |   0 | fuente (lib/)   |
| lwIP     | 2.1.2   |       8 |    2 |    6 |   0 |   0 | fuente (lib/)   |
| SQLite   | 3.39.1  |       6 |    0 |    3 |   3 |   0 | amalgamación    |
| zlib     | 1.2.11  |       4 |    2 |    2 |   0 |   0 | fuente (lib/)   |
| **Total**|         | **196** | **15**| **75**|**95**|**10**|              |

---

## Fase 1 — Análisis SBOM (GT = 129 CVEs)

El escenario de entrada es un SBOM CycloneDX 1.4 generado desde `vcpkg.json` con seis componentes declarados (curl, OpenSSL, expat, libpng, SQLite, zlib) incluyendo campos CPE y PURL explícitos.

| Herramienta            | TP  | FP | FN  | Precisión | Recall | F1        | Tiempo |
|------------------------|-----|----|-----|----------:|-------:|-----------|-------:|
| **Grype v0.109**       | 120 |  9 |   9 |    93,0 % | 93,0 % | **0,930** |   22 s |
| Dependency-Track v4.11 | 102 |  1 |  27 |    99,0 % | 79,1 % | **0,879** |  ~12 s |
| Trivy v0.69            |   0 |  0 | 129 |       N/D |  0,0 % | 0,000     |    1 s |
| Snyk v1.x              |   0 |  0 | 129 |       N/D |  0,0 % | 0,000     |   11 s |

### Análisis de resultados

**Grype (F1=0,930)** — Mejor resultado global de la fase. Los 9 FP son CVEs con rangos de versión mal definidos en la base de datos de Grype (e.g., CVEs de rama OpenSSL 3.x reportados sobre 1.0.2k). Los 9 FN son CVEs recientes (2024-2026) no cubiertos en el snapshot de la DB.

**Dependency-Track (F1=0,879)** — Precisión muy alta (99,0%: solo 1 FP genuino), pero 27 FN respecto a Grype. Su principal caso de uso es la monitorización continua de un SBOM persistente, no la integración en CI/CD por commit.

**Trivy (F1=0,000)** — No detecta vulnerabilidades en SBOMs CycloneDX con componentes C/C++ nativos definidos por CPE/PURL genérico. Su ecosistema objetivo son imágenes de contenedor y paquetes de sistema operativo.

**Snyk (F1=0,000)** — No soporta `vcpkg` como gestor de paquetes C/C++. El F1=0,000 es una limitación del ecosistema, no de la herramienta en general (ofrece capacidad real en Fase 2 con `--unmanaged`).

### Validación ecológica — Mosquitto v2.0.18

Grype y Trivy sobre el SBOM generado con `syft dir:` sobre las fuentes de Mosquitto produjeron 0 detecciones. Causa: `syft dir:` no resuelve dependencias declaradas vía CMake `find_package()`. El SBOM resultante solo incluye componentes de los workflows de CI, no las dependencias reales de compilación.

**Lección metodológica:** Para proyectos CMake con dependencias del sistema, el método correcto de generación de SBOM es `syft image:` sobre la imagen Docker final.

### Decisión técnica

- **Seleccionado:** Grype v0.109 para integración en CI/CD (F1=0,930, 22 s, operación local).
- **Complementario:** Dependency-Track v4.11 como plataforma de monitorización continua (Precisión=99,0%).

---

## Fase 2 — Dependencias vendorizadas (GT = 49 CVEs)

El escenario de entrada es el directorio `lib/` con el código fuente de cinco librerías copiadas directamente al repositorio (sin gestor de paquetes).

| Herramienta              | TP | FP | FN | Precisión | Recall | F1        | Tiempo    |
|--------------------------|----|----|----|-----------:|-------:|-----------|----------:|
| **Snyk --unmanaged**     | 39 |  8 | 10 |     83,0 % | 79,6 % | **0,812** |      40 s |
| OWASP DC v11.1.1         |  6 | 22 | 43 |     21,4 % | 12,2 % | 0,156     | 4 s (*)   |
| FOSSA / ORT / ScanCode   |  0 |  0 | 49 |       N/D |  0,0 % | 0,000     | —         |

(*) Con base de datos cacheada. Primera ejecución con descarga NVD completa: ~25 min.

### Análisis de resultados

**Snyk --unmanaged (F1=0,812)** — Única herramienta con capacidad real de fingerprinting de código fuente C/C++ sin gestor de paquetes. Calcula hashes de los ficheros fuente y los consulta contra la API de Snyk.

- **FP (8):** CVEs con versiones fuera del rango afectado de las librerías del corpus (e.g., CVEs de libpng ≥1.6.43 reportados sobre 1.6.34).
- **FN estructural (7):** lwIP 2.1.2 no cubierto en la base de firmas de Snyk.
- **Limitación operativa:** Requiere conexión a `api.snyk.io` en tiempo de ejecución — incompatible con entornos aislados sin conectividad externa.

**OWASP DC (F1=0,156)** — F1 muy inferior al de Snyk. Tasa de FP del 78% debida a falsos matches de nombre de archivo en el analizador experimental C++ (confunde librerías genéricas como `libmagic` o `libarchive` con las del corpus). Solo detecta las librerías con nombres de fichero más reconocibles (libpng, zlib). Ventaja: puede operar sin conectividad externa con feeds NVD descargados localmente.

**FOSSA, ORT, ScanCode (F1=0,000)** — Completamente ineficaces para detección de CVEs en código C/C++ sin gestor de paquetes. Su propósito es el análisis de licencias y la generación de SBOM, no el escaneo de vulnerabilidades por fingerprinting.

### Validación ecológica — Contiki-NG v4.9

Snyk --unmanaged sobre el repositorio de Contiki-NG v4.9 (GT mínimo = 8 CVEs de tinyDTLS):

| Herramienta      | TP | FP | FN | Recall | F1    |
|------------------|----|----|-----|--------|-------|
| Snyk --unmanaged |  6 |  9 |  2 | 75,0 % | 0,522 |

Los 9 FP son CVEs reales de Contiki-NG core (fuera del GT mínimo definido sobre tinyDTLS). Los 2 FN corresponden a vulnerabilidades de comportamiento en tiempo de ejecución (PRNG débil, DoS por flooding) difíciles de detectar por fingerprinting estático.

### Decisión técnica

- **Seleccionado:** Snyk --unmanaged (F1=0,812) para entornos con conectividad externa.
- **Alternativa en entorno aislado:** OWASP DC v11.1.1 (única opción viable sin red; F1=0,156).

---

## Fase 3 — Análisis binario (GT efectivo = 37 CVEs)

El escenario de entrada es el binario ELF `build/mi-gateway` compilado a partir del corpus. El GT efectivo (37 CVEs) restringe la evaluación a las librerías para las que las herramientas de análisis binario tienen capacidad técnica real: aquellas que embeben su versión semántica como string en el ELF (expat 2.4.6, libpng 1.6.34, SQLite 3.39.1, zlib 1.2.11).

> Los 59 CVEs de mbedTLS (35) y wolfSSL (24) son **estructuralmente indetectables** por string-matching de versión semántica: los binarios precompilados solo exponen la versión ABI, no la versión semántica.

| Herramienta              | TP | FP | FN  | Precisión | Recall | F1 (GT_eff) | Tiempo   |
|--------------------------|----|----|-----|----------:|-------:|-------------|----------|
| **EMBA v2.0.0**          | 23 | 13 |   3 |    63,9 % | 88,5 % | **0,743**   | 10.241 s |
| **CVE-Binary-Tool v3.4** | 16 |  3 |  21 |    84,2 % | 43,2 % | **0,571**   | 10 s     |
| Grype (binario) v0.109   |  0 |  0 |  37 |       N/D |  0,0 % | 0,000       | 9 s      |
| Trivy (binario) v0.69    |  0 |  0 |  37 |       N/D |  0,0 % | 0,000       | <1 s     |

### Análisis de resultados

**EMBA v2.0.0 (F1=0,743)** — Framework de análisis de firmware embebido. Ejecuta 60+ módulos de detección (CVE via módulo F17 con CVE-bin-tool, checksec sobre protecciones binarias, análisis de weak functions, SBOM CycloneDX). Mayor recall (88,5%) que CBT a costa de mayor tasa de FP (63,9% precisión) y tiempo de ejecución de ~2h50m.

Resultados por librería (EMBA):

| Librería | CVEs detectados | TP | FP | FN | Precisión | Recall | F1    |
|----------|----------------:|----|----|----|-----------:|-------:|-------|
| expat    |              16 | 15 |  1 |  0 |     93,8 % | 100 %  | 0,968 |
| zlib     |               6 |  4 |  2 |  0 |     66,7 % | 100 %  | 0,800 |
| SQLite   |               4 |  4 |  0 |  0 |    100,0 % | 100 %  | 1,000 |
| libpng   |              10 |  0 | 10 |  3 |      0,0 % |   0 %  | 0,000 |

**CVE-Binary-Tool v3.4 (F1=0,571)** — Ultrarrápido (10 s). Alta precisión (84,2%) con 3 FP. Recall moderado (43,2%): detecta solo los CVEs de librerías con versión bien embebida y cubiertos en su snapshot de base de datos.

**Grype y Trivy sobre ELF (F1=0,000)** — Sin detecciones sobre el binario ELF sin SBOM asociado. Ambas herramientas son efectivas solo cuando se les proporciona un SBOM externo o analizan imágenes Docker con metadatos de paquetes del sistema operativo.

**Hallazgos complementarios de EMBA:**
- `s11_binary_protections`: NX=habilitado ✓, PIE=deshabilitado ✗, Stack Canary=none ✗
- `s05_weak_functions`: 0 funciones peligrosas críticas detectadas (strcpy, gets)
- Recomendación: compilar con `-fPIE -pie -fstack-protector-strong`

### Decisión técnica

- **Gate rápido CI/CD:** CVE-Binary-Tool v3.4 (10 s, alta precisión, embebible en pipeline por commit).
- **Verificación profunda nightly:** EMBA v2.0.0 (mayor recall, análisis de firmware completo, ejecución post-build).

---

## Cobertura acumulada del pipeline completo

Herramientas seleccionadas: Grype (F1) + Snyk --unmanaged (F2) + CVE-Binary-Tool (F3).

| Fase | Herramienta | TPs nuevos | TPs acumulados | GT fase |
|------|-------------|------------|----------------|--------:|
| Fase 1 | Grype v0.109 | 120 | 120 | 129 |
| Fase 2 | Snyk --unmanaged | +9 | 129 | 49 |
| Fase 3 | CVE-Binary-Tool v3.4 | +3 | 132 | 196 |
| **Total** | | | **≥132** | **196** |

- **Cobertura bruta:** 132 / 196 = **67,3 %**
- **Cobertura efectiva** (excluyendo 59 CVEs estructuralmente indetectables): 132 / 137 = **≈ 96,4 %**

Áreas de baja cobertura restantes:
- **lwIP (8 CVEs):** FN estructural en Snyk --unmanaged (base de firmas no cubre lwIP).
- **expat parcial:** 2 FN en Fase 2; 2 FN adicionales en Fase 3.

---

## Tiempos de ejecución

| Fase | Herramienta | Tiempo real | Cuello de botella |
|------|-------------|-------------|:-----------------:|
| Fase 1 | Syft (generación SBOM) | 113 s | ★ |
| Fase 1 | Grype (scan SBOM) | 22 s | |
| Fase 1 | Dependency-Track (API) | ~12 s | |
| Fase 1 | Trivy (scan SBOM) | 1 s | |
| Fase 1 | Snyk (vcpkg) | 11 s | |
| Fase 2 | Snyk --unmanaged | 40 s | ★ |
| Fase 2 | OWASP DC (DB cacheada) | 4 s | |
| Fase 2 | OWASP DC (primera vez) | ~1.500 s | ★★ |
| Fase 3 | CVE-Binary-Tool | 10 s | |
| Fase 3 | Grype (binario) | 9 s | |
| Fase 3 | Trivy (binario) | <1 s | |
| Fase 3 | EMBA | 10.241 s | ★★ |

**Pipeline completo ejecutado (Syft + Grype + Snyk --unmanaged + CBT):** ~187 s (~3 min)

---

## Decisión final por escenario

| Escenario | Herramienta seleccionada | F1 | Justificación |
|-----------|--------------------------|-----|---------------|
| SBOM (CI/CD por commit) | Grype v0.109 | **0,930** | Mejor F1 global; rápido (22 s); operación local; integración GitHub Actions nativa |
| SBOM (monitorización) | Dependency-Track v4.11 | **0,879** | Precisión 99,0%; plataforma de gestión continua de SBOM |
| Vendoring (con red) | Snyk --unmanaged | **0,812** | Única opción viable con capacidad real de fingerprinting C/C++ |
| Vendoring (sin red) | OWASP DC v11.1.1 | **0,156** | Operable con feeds NVD locales; FP elevados requieren triaje manual |
| Binario (gate rápido) | CVE-Binary-Tool v3.4 | **0,571** | 10 s; alta precisión (84,2%); embebible en pipeline por commit |
| Binario (análisis profundo) | EMBA v2.0.0 | **0,743** | Mayor recall (88,5%); 60+ módulos; análisis firmware completo; nightly |

---

## Limitaciones

1. **Snyk --unmanaged requiere conectividad externa** en tiempo de ejecución, lo que lo hace incompatible con entornos de ejecución aislados.
2. **OWASP DC FP rate del 78 %** en código C/C++ embebido por falsos matches de nombre de archivo.
3. **FN estructurales en Fase 3** para mbedTLS (35 CVEs) y wolfSSL (24 CVEs): los binarios precompilados no contienen la versión semántica embebida como string.
4. **lwIP no cubierto por Snyk --unmanaged**: FN estructural de 7-8 CVEs por ausencia en la base de firmas.
5. **Syft `dir:` ineficaz sobre CMake**: No resuelve `find_package()`; usar `syft image:` sobre imagen Docker.
6. **EMBA no apto como gate bloqueante**: coste temporal de ~2h50m por ejecución.

---

## Referencias

Los resultados completos con análisis detallado por herramienta, librería y fase están disponibles en [docs/BENCHMARK_HIBRIDO_FINAL.md](docs/BENCHMARK_HIBRIDO_FINAL.md).

Las métricas en formato estructurado se encuentran en [docs/metrics_final.json](docs/metrics_final.json).

El diseño experimental y las consideraciones metodológicas se describen en [docs/BENCHMARK_METHODOLOGY.md](docs/BENCHMARK_METHODOLOGY.md).
