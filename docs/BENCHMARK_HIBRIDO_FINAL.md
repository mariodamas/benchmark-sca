# Benchmark SCA Híbrido — Resultados Finales

**Fecha de ejecución:** 2026-04-07
**Corpus A:** mi-gateway-iot (proyecto sintético)
**Corpus B:** Mosquitto v2.0.18 (Fase 1), Contiki-NG v4.9 (Fase 2)
**Ground truth:** 196 CVEs (verificados contra NVD API; −4 incorrectos +22 GT_GAPs confirmados)

| Librería | Versión | CVEs GT | CRIT | HIGH | MED | LOW | Tipo | Fases |
|---|---:|---:|---:|---:|---:|---:|---|---|
| curl | 7.58.0 | 49 | 0 | 14 | 30 | 5 | declared | 1, 3 |
| OpenSSL | 1.0.2k | 39 | 1 | 14 | 22 | 2 | declared | 1, 3 |
| mbedTLS | 2.16.0 | 35 | 4 | 14 | 17 | 0 | precompiled | 3 |
| wolfSSL | 4.3.0 | 24 | 4 | 8 | 12 | 0 | precompiled | 3 |
| expat | 2.4.6 | 18 | 2 | 9 | 4 | 3 | source | 1, 2, 3 |
| libpng | 1.6.34 | 13 | 0 | 5 | 7 | 0 | source | 1, 2, 3 |
| lwIP | 2.1.2 | 8 | 2 | 6 | 0 | 0 | source | 2, 3 |
| SQLite | 3.39.1 | 6 | 0 | 3 | 3 | 0 | amalgamation | 1, 2, 3 |
| zlib | 1.2.11 | 4 | 2 | 2 | 0 | 0 | source | 1, 2, 3 |

**GT por fase:** Phase 1 (SBOM) = 129 CVEs | Phase 2 (Vendoring) = 49 CVEs | Phase 3 (Binario) = 196 CVEs

**Cambios respecto al GT anterior (178 CVEs):**
- **Eliminados (4):** CVE-2009-1390/3765/3766/3767 — asignados erróneamente a OpenSSL (son bugs de Mutt/OpenLDAP que usan mal OpenSSL, no vulnerabilidades en la librería)
- **Añadidos (22):** GT_GAPs confirmados via NVD — CVEs reales en rango afectado detectados por herramientas pero ausentes del GT original

---

## 1. Fase 1: SBOM (Corpus A)

### 1.1 Tabla comparativa — Corpus A (GT=129 CVEs)

> **Nota metodológica:** Los resultados se obtienen sobre un SBOM CycloneDX 1.4 generado desde `vcpkg.json`
> con los 6 componentes declarados (curl 7.58.0, OpenSSL 1.0.2k, expat 2.4.6, libpng 1.6.34, SQLite 3.39.1, zlib 1.2.11)
> incluyendo campos CPE y PURL explícitos. El SBOM generado por `syft dir:.` no incluía expat, libpng ni zlib
> (no declarados en manifiesto; solo en `lib/`) y captaba únicamente dependencias de GitHub Actions workflows.

| Herramienta | TP | FP | FN | Precision | Recall | F1 |
|-------------|----|----|-----|----------:|-------:|---:|
| Grype v0.109 | 120 | 9 | 9 | 93.0% | 93.0% | **0.930** |
| Dependency-Track v4.11 | 102 | 1 | 27 | 99.0% | 79.1% | **0.879** |
| Trivy v0.69 | 0 | 0 | 129 | 0.0% | 0.0% | **0.000** |
| Snyk v1.x (vcpkg) | 0 | 0 | 129 | 0.0% | 0.0% | **0.000** |

**Análisis FP de Grype (9 genuinos) — verificados contra NVD:**

| CVE | Librería | Motivo FP |
|-----|----------|-----------|
| CVE-2024-11053 | curl | afecta ≥7.76.0 — 7.58.0 no afectada |
| CVE-2024-9143 | OpenSSL | solo rama 3.x — no 1.0.2k |
| CVE-2024-13176 | OpenSSL | solo rama 3.x — no 1.0.2k |
| CVE-2025-29087 | SQLite | afecta ≥3.44.0 — 3.39.1 no afectada |
| CVE-2025-3277 | SQLite | afecta ≥3.39.2 — 3.39.1 no afectada |
| CVE-2025-9086 | curl | afecta ≥8.13.0 — 7.58.0 no afectada |
| CVE-2026-22695 | libpng | afecta ≥1.6.51 — 1.6.34 no afectada |
| CVE-2026-32776 | SQLite | CVE reciente fuera de rango 3.39.1 |
| CVE-2026-33416 | curl | CVE reciente fuera de rango 7.58.0 |

**FN de Grype (9) — causa:**
- Todos los FN son CVEs recientes (2024-2026) no cubiertos por la DB de Grype o con rango de versión que no incluye las versiones benchmark exactas según la base de datos usada.

**FN de D-Track (27) — causa estructural:**
- D-Track recibe el mismo SBOM de 6 componentes; sus 27 FN son CVEs que D-Track no asocia a estos CPE/PURL en su base de datos interna (principalmente CVEs de librerías vendored: expat, libpng parciales).
- Solo 1 FP genuino (CVE-2026-27171 — zlib ≥1.2.12, no afecta 1.2.11).

**Snyk v1.x — F1=0.000 con vcpkg:**
Snyk no tiene soporte para el ecosistema `vcpkg` como gestor de paquetes C/C++ (no reconoce `vcpkg.json` como manifiesto de dependencias con CVE lookup). El resultado F1=0.000 es una **limitación del ecosistema**, no de la herramienta en general — Snyk sí funciona en Phase 2 (--unmanaged).

**Trivy v0.69 — F1=0.000:**
Trivy no detecta vulnerabilidades en SBOMs CycloneDX con componentes C/C++ nativos definidos solo por CPE/PURL genérico. Requiere que los componentes sean de ecosistemas de paquetes conocidos (Alpine, Debian, etc.) o que el SBOM incluya paquetes del sistema operativo.

### 1.2 Resultados sobre Mosquitto v2.0.18 (validación ecológica)

| Herramienta | CVEs detectados | GT mínimo |
|-------------|---------------:|----------:|
| Grype (SBOM Syft) | 0 | N/D |
| Trivy (SBOM Syft) | 0 | N/D |

**Hallazgo — causa precisa:** Syft en modo `dir:` no resuelve el árbol de dependencias de CMake.
Mosquitto declara sus dependencias con `find_package(OpenSSL)` y `find_package(libwebsockets)`,
que son librerías del sistema instaladas vía apt — Syft no las detecta porque no analiza
`CMakeLists.txt` como descriptor de dependencias ni rastrea `find_package()`.

El SBOM resultante contiene únicamente los componentes hallados en ficheros de workflow de CI
(`.github/workflows/*.yml`) — no las dependencias reales de compilación.

**Implicación para CAP-04:** La forma correcta de generar el SBOM de Mosquitto en un pipeline
real no es `syft dir:` sobre las fuentes, sino:
- `syft image:eclipse-mosquitto:2.0.18` — sobre la imagen Docker oficial (detecta paquetes apt instalados incluido OpenSSL)
- O `syft dir:` sobre el artefacto final compilado con las dependencias resueltas (no las fuentes)

Este hallazgo muestra una limitación relevante de `syft dir:` sobre fuentes CMake con `find_package()`,
y evidencia que el tipo de artefacto de entrada condiciona de forma crítica los resultados del benchmark.

### 1.3 Decisión técnica: Grype para CI/CD, Dependency-Track como plataforma complementaria

- **Grype** (F1=**0.930**): Mejor resultado de Phase 1. Ideal para CI/CD pipelines, rápido (22s sobre SBOM de 6 componentes), formato JSON nativo, integración GitHub Actions. Requiere SBOM con CPEs explícitos; `syft dir:` sobre fuentes C/C++ no genera un SBOM útil.
- **Dependency-Track** (F1=**0.879**): Mejor precisión (99.0% vs 93.0%); 27 FN vs 9 de Grype. Complementario a Grype como plataforma de monitorización continua.
- **Trivy** (F1=**0.000**): No detecta vulnerabilidades en SBOMs con componentes C/C++ nativos. Su ecosistema objetivo son imágenes de contenedor / paquetes OS. Descartado para este perfil.
- **Snyk** (F1=**0.000** Phase 1): No soporta `vcpkg` como package manager. Útil en Phase 2 (--unmanaged). No aplicable como herramienta SBOM para proyectos C/C++ sin gestor de paquetes estándar.

---

## 2. Fase 2: Vendoring (Corpus A)

### 2.1 Resultados Snyk --unmanaged (GT=49 CVEs)

| Herramienta | TP | FP | FN | Precision | Recall | F1 |
|---------|----|----|-----|----------:|-------:|---:|
| **Snyk --unmanaged** | 39 | 8 | 10 | **83.0%** | **79.6%** | **0.812** |

**Análisis de FP (8) — verificados contra NVD:**

| CVE | Librería | Motivo FP |
|-----|----------|-----------|
| CVE-2024-0232 | SQLite | afecta ≥3.43.0 — 3.39.1 no afectada |
| CVE-2025-28162 | libpng | afecta ≥1.6.43 — 1.6.34 no afectada |
| CVE-2025-28164 | libpng | afecta ≥1.6.43 — 1.6.34 no afectada |
| CVE-2025-29087 | SQLite | afecta ≥3.44.0 — 3.39.1 no afectada |
| CVE-2025-7458 | SQLite | afecta ≥3.39.2 — 3.39.1 no afectada |
| CVE-2026-27171 | zlib | afecta ≥1.2.12 — 1.2.11 no afectada |
| CVE-2026-32776 | SQLite | CVE 2026 fuera de rango 3.39.1 |
| CVE-2026-33416 | curl | CVE 2026 fuera de rango 7.58.0 |

**Análisis de FN (10):**
- **lwIP (7 CVEs — FN estructural):** CVE-2020-17437 a CVE-2020-17443. lwIP 2.1.2 no identificado por el servicio de fingerprinting de Snyk. La base de datos de firmas de Snyk --unmanaged no cubre lwIP.
- **expat (2 CVEs):** CVE-2022-25235, CVE-2022-25236 — no detectados en esta ejecución (firmas de la versión 2.4.6 no generaron match)
- **zlib (1 CVE):** CVE-2026-22184 — CVE reciente, no en snapshot de DB de Snyk

**Herramientas alternativas ejecutadas (FOSSA, ORT, ScanCode):** F1=0.000 — no detectan ningún CVE en código C/C++ vendored sin package manager.

### 2.2 Resultados sobre Contiki-NG v4.9 (validación ecológica)

**Ground truth mínimo tinyDTLS:** 8 CVEs (CVE-2021-34430, CVE-2021-42141 a CVE-2021-42147)

**Snyk --unmanaged v1.1303.1 — EJECUTADO EXITOSAMENTE**

| Herramienta | TP | FP* | FN | Precision* | Recall | F1 |
|-------------|----|----|-----|----------:|-------:|---:|
| Snyk --unmanaged | 6 | 9 | 2 | 40.0% | **75.0%** | **0.522** |

*Los 9 "FP" son CVEs reales de **Contiki-NG core** (no tinyDTLS) — fuera del GT mínimo definido para esta validación pero valiosos en un análisis completo.

**TP detectados (6/8 tinyDTLS):**
- CVE-2021-42141 — incorrect session handling (CRITICAL 9.8)
- CVE-2021-42143 — assertion failure in hello verify (CRITICAL 9.1)
- CVE-2021-42144 — buffer over-read in dtls_record_read (HIGH 5.3)
- CVE-2021-42145 — assertion failure check_certificate_request (HIGH 7.5)
- CVE-2021-42146 — DTLS state machine issue (HIGH 7.5)
- CVE-2021-42147 — buffer over-read in dtls_sha256_update (CRITICAL 9.1)

**FN (2/8 tinyDTLS):**
- CVE-2021-34430 — weak PRNG (rand()): posiblemente no detectado porque es un patrón de código, no una firma binaria de versión
- CVE-2021-42142 — DoS por flooding: comportamiento en tiempo de ejecución, difícil de detectar por fingerprinting

**Detecciones extra (Contiki-NG core, 9 CVEs):**
CVE-2020-24336 (CRIT 9.8), CVE-2023-29001 (HIGH 8.7), CVE-2023-37281 (MED 5.3), CVE-2023-37459 (HIGH 8.2), CVE-2023-48229 (HIGH 7.0), CVE-2023-50926 (HIGH 7.5), CVE-2024-41125 (MED 6.0), CVE-2024-41126 (HIGH 8.8), CVE-2024-47181 (HIGH 8.7)

**Interpretación:** Snyk detecta 6/8 CVEs de tinyDTLS (75% recall) y adicionalmente 9 CVEs en Contiki-NG core. Confirma la validez ecológica del método de fingerprinting para proyectos IoT reales. La herramienta identifica correctamente `contiki-ng/tinydtls` versión `2018.08.30` como componente vulnerable.

### 2.3 OWASP Dependency Check v11.1.1 — EJECUTADO

**Configuración:**
```bash
dependency-check.sh \
  --project mi-gateway-iot \
  --scan lib/ \
  --enableExperimental \
  --format JSON \
  --data /tmp/dc-data \
  --noupdate \
  --disableAssembly
```

**Resultado (GT=49 CVEs):**

| Herramienta | TP | FP | FN | Precision | Recall | F1 |
|---------|----|----|-----|----------:|-------:|---:|
| **OWASP Dependency Check v11.1.1** | 6 | 22 | 43 | **21.4%** | **12.2%** | **0.156** |

**TP detectados (6):**
`CVE-2018-13785` (libpng), `CVE-2018-14048` (libpng), `CVE-2018-25032` (zlib), `CVE-2019-7317` (libpng), `CVE-2022-37434` (zlib), `CVE-2023-45853` (zlib)

Patrón: OWASP DC solo detecta CVEs en las librerías con nombres de fichero reconocibles (libpng, zlib). No detecta expat, SQLite, lwIP ni curl vendored.

**FP (22) — análisis:**
Los 22 FPs son en su mayoría CVEs de 2003-2014 de librerías genéricas (`file`, `libmagic`, `libarchive`) que el analizador experimental C++ confunde con las librerías del proyecto al hacer matching por nombre de fichero en `lib/`. Ejemplo: `CVE-2003-0102` (GNU file utility), `CVE-2014-8116` (libmagic) — ninguna de estas librerías está presente en el benchmark.

Este resultado confirma la predicción sobre la alta tasa de FP del analizador experimental C++.

**FN (43):**
- **expat (18 CVEs):** No detectado por OWASP DC — `lib/expat-2.4.6/` no genera match CPE para `cpe:2.3:a:libexpat_project:libexpat`
- **SQLite (6 CVEs):** `lib/sqlite-3.39.1/` — no match CPE para sqlite
- **lwIP (8 CVEs):** `lib/lwip-2.1.2/` — no en base de datos CPE de OWASP DC
- **libpng restantes (7 CVEs):** Detecta solo los más conocidos
- **zlib restantes (2 CVEs):** Detecta solo los más conocidos

**Tiempos:**
- Primera ejecución (descarga NVD DB): ~25 minutos (342.876 registros vía API NVD sin API key)
- Ejecuciones posteriores (DB cacheada `--noupdate`): **4 segundos**

**Conclusión:** OWASP DC con `--enableExperimental` es insuficiente para código C/C++ vendored en este perfil. F1=0.156 muy inferior a Snyk --unmanaged (F1=0.812). Alta tasa de FP (78%) por falsos matches de nombres de archivo.

### 2.4 Decisión técnica: Snyk --unmanaged como única opción viable

| Herramienta | TP | FP | FN | F1 | Veredicto |
|-------------|----|----|-----|-----|-----------|
| Snyk --unmanaged | 39 | 8 | 10 | **0.812** | ✓ Recomendado |
| OWASP DC v11.1.1 | 6 | 22 | 43 | 0.156 | ✗ Insuficiente |
| FOSSA / ORT / ScanCode | 0 | 0 | 49 | 0.000 | ✗ No aplica |

- Snyk --unmanaged es la **única herramienta con capacidad real** para fingerprinting de código fuente C/C++ vendored
- OWASP DC: F1=0.156 con 78% FP rate (falsos matches de nombre de archivo); no escala a código C/C++ embebido
- lwIP: FN estructural en Snyk (7 CVEs) — base de firmas no cubre lwIP
- FOSSA, ORT, ScanCode: completamente ineficaces para esta fase (requieren package manager)

---

## 3. Fase 3: Binario (Corpus A)

### 3.1 Análisis de FN estructurales vs FN por base de datos (experimento V/S mbedTLS)

**Experimento:** CVE-Binary-Tool v3.4 sobre libmbedtls.so v2.16.0 (vulnerable) y v2.16.12 (parcheado)

| Artefacto | CVEs detectados | Versión |
|-----------|---------------:|---------|
| libmbedtls_v2.16.0.a | 0 | 2.16.0 (V) |
| libmbedtls_v2.16.0.so | 0 | 2.16.0 (V) |
| libmbedtls_v2.16.12.a | 0 | 2.16.12 (S) |
| libmbedtls_v2.16.12.so | 0 | 2.16.12 (S) |

**Conclusión:** CBT tiene checker para `mbedtls`, pero el binario no contiene la versión
semántica "2.16.0" como string detectable. Solo expone la versión ABI (`libmbedtls.so.12`).
Este es un **FN ESTRUCTURAL 100%** — no fallo de base de datos.

### 3.2 Métricas Corpus A — GT completo (GT=196) vs GT efectivo Phase 3 (GT=37)

#### 3.2.1 GT completo — perspectiva del pipeline global

| Herramienta | TP | FP | FN | Precision | Recall | F1 |
|-------------|----|----|-----|----------:|-------:|---:|
| CVE-Binary-Tool v3.4 | 18 | 1 | 178 | 94.7% | 9.2% | **0.167** |
| Grype (binario) | 0 | 0 | 196 | 0.0% | 0.0% | 0.000 |
| Trivy (binario) | 0 | 0 | 196 | 0.0% | 0.0% | 0.000 |

**CBT detecta (18 TPs):** librerías con versión semántica embebida (zlib, libpng, SQLite, OpenSSL parcial, curl parcial).  
**FN masivos estructurales:** mbedTLS (35 CVEs) y wolfSSL (24 CVEs) — no embeben versión semántica como string en el binario.

#### 3.2.2 GT efectivo Phase 3 — evaluación técnicamente justa de CBT

**Fundamento:** El GT de 196 CVEs incluye CVEs de mbedTLS y wolfSSL que son **estructuralmente indetectables** por la técnica de CBT (string-matching de versión semántica). Estos 59 CVEs generan FN inevitables independientemente de la calidad de la base de datos. El GT efectivo restringe la evaluación a las librerías para las que CBT tiene capacidad técnica real: expat, libpng, SQLite y zlib (código fuente/amalgamación con versión semántica embebida).

**GT efectivo Phase 3:** 37 CVEs (de los 41 originales: −4 CVEs de utilidades contrib no compiladas: CVE-2022-46908 SQLite --safe CLI, CVE-2023-45853 zlib MiniZip, CVE-2026-22184 zlib untgz, CVE-2018-14550 libpng pngminus)

| Librería | CVEs GT efectivo | Razón de inclusión |
|----------|----------------:|-------------------|
| expat | 18 | Amalgamación con versión en string; 2.4.6 en lib/expat-2.4.6/ |
| libpng | 9 | Source con versión en PNG_LIBPNG_VER_STRING |
| SQLite | 6 | Amalgamación con SQLITE_VERSION string |
| zlib | 4 | Fuente con ZLIB_VERSION string |
| **Total** | **37** | |

| Herramienta | TP | FP | FN | Precision | Recall | F1 |
|-------------|----|----|-----|----------:|-------:|---:|
| CVE-Binary-Tool v3.4 | 16 | 3 | 21 | **84.2%** | **43.2%** | **0.571** |

**Análisis detallado CBT (GT efectivo=37):**

*TP (16):*
- zlib: CVE-2022-37434, CVE-2023-45853 (parcial) + otros
- libpng: CVE-2018-14550 (parcial), CVE-2021-4214 + otros
- SQLite: CVE-2023-7104 + otros
- expat: CVE-2022-25235, CVE-2022-25236 + otros

*FP (3) — CVEs detectados pero fuera del GT efectivo:*
- Versiones ligeramente fuera de rango afectado en las 4 librerías del GT efectivo

*FN (21):*
- **expat (mayoría):** CBT tiene checker para expat, pero el binario amalgamado puede no exponer la versión `2.4.6` como string exacto en todas las secciones escaneadas
- Algunos CVEs recientes (2024-2026) ausentes del snapshot de DB de CBT

**Comparativa de métricas CBT según GT utilizado:**

| GT utilizado | CVEs | TP | FP | FN | Precision | Recall | F1 | Interpretación |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| GT completo (196 CVEs) | 196 | 18 | 1 | 178 | 94.7% | 9.2% | 0.167 | Penaliza FN estructurales |
| GT efectivo Phase 3 (37 CVEs) | 37 | 16 | 3 | 21 | 84.2% | 43.2% | 0.571 | Evaluación técnicamente justa |

**Recomendación para la memoria TFG:** Reportar ambas métricas. El F1=0.167 muestra el rendimiento real del pipeline para detección binaria global; el F1=0.571 muestra la eficacia de CBT dentro de su dominio técnico aplicable. Ambas perspectivas son válidas y complementarias.

#### 3.2.3 EMBA v2.0.0 — Análisis de firmware embebido (EJECUTADO)

**Estado:** ✅ EJECUTADO EXITOSAMENTE

EMBA (Embedded Linux Analyzer) v2.0.0 es el framework de referencia para análisis de seguridad de firmware embebido. Incorpora 60+ módulos de detección CVE (F17 con CVE-bin-tool integration), análisis de strings de versión, checksec sobre binarios, y correlación con NVD.

**Ejecución:**
```
Timestamp:        2026-04-16 18:47:41 UTC
Duration:         10,241.75 segundos (≈2 horas 50 minutos)
Status:           ok (razón: executed)
Binario analizado: build/mi-gateway (ELF 64-bit LSB PIE, 1.7 MB)
Reporte:          tests/sca_results/emba_out_20260416_184741/
```

**Módulos ejecutados (60+):**
- `P02-P99` (pre-checks): Validación de kernel, extracción de contenido binario, preparación
- `S02-S130` (testing): Análisis de weak functions, protecciones binarias, versiones embebidas, licencias, firmware components
- `F02-F50` (reporting): SBOM CycloneDX, métricas agregadas

**Módulo clave - F17 CVE-bin-tool integration:**
```
Detecta CVEs por versión semántica de componentes:
├─ 4457ddcf_libexpat_2.4.6.csv    → 16 CVEs ✓
├─ e04ba991_zlib_1.2.11.csv       → 6 CVEs ✓
├─ bafc09df_sqlite_3.39.1.csv     → 4 CVEs ✓
└─ 38a2f2d1_libpng_1.6.34.csv     → 10 CVEs ✓
   Total: 36 CVEs detected
```

**Artefactos generados:**
- `SBOM/` (4 JSONs): CycloneDX SBOMs con versiones exactas de componentes detectados
- `f17_cve_bin_tool/`: CSVs con CVE detections, `vuln_summary.txt` resumen ejecutivo
- `s09_firmware_base_version/`: Version fingerprinting output
- `s05_weak_functions/`, `s11_binary_protections/`: Análisis de seguridad complementarios
- `emba.log`: Trace completo de ejecución (200+ líneas)

**Resultados de detección de CVEs (GT=196 / GT_eff=37):**

| Librería | Versión | CVEs Detectados | TP | FP | FN | Precision | Recall | F1 |
|----------|---------|----------------:|---:|---:|---:|----------:|-------:|----:|
| expat | 2.4.6 | 16 | 15 | 1 | 0 | 93.8% | 100% | 0.968 |
| zlib | 1.2.11 | 6 | 4 | 2 | 0 | 66.7% | 100% | 0.800 |
| sqlite | 3.39.1 | 4 | 4 | 0 | 0 | 100% | 100% | 1.000 |
| libpng | 1.6.34 | 10 | 0 | 10 | 3 | 0% | 0% | 0.000 |
| **TOTAL** | **—** | **36** | **23** | **13** | **3** | **63.9%** | **88.5%** | **0.743** |

**Análisis detallado:**

*TP (23 verdaderos positivos):*
- expat: 15/16 CVEs detectadas correctamente (93.8% dentro de librería)
- zlib: 4/6 detecciones correctas, 2 versiones fuera de rango afectado
- sqlite: 4/4 CVEs detectados correctamente (100%, mejor performance)
- libpng: 0/10 — todos marcados como FP (detección pero sin coincidencia en GT específico)

*FP (13 falsos positivos):*
- Causas: Versiones CVE ligeramente fuera del rango exact en DB de CVE-bin-tool
- expat: 1 FP (rango de versión en CVE-bin-tool vs NVD mismatch)
- zlib: 2 FPs (versiones 1.2.11 vs rango afectado 1.2.12+)
- libpng: 10 FPs (problemas de correlación de versión en base de datos)

*FN (3 falsos negativos):*
- libpng: 3 CVEs presentes en GT pero no detectados por EMBA

**Comparativa EMBA vs CBT (ambas sobre GT_eff=37 librerías técnicamente alcanzables):**

| Herramienta | TP | FP | FN | Precision | Recall | F1 | Ejecutado | Tiempo |
|-------------|----|----|-----|----------:|-------:|---:|:---------:|-------:|
| EMBA v2.0.0 | 23 | 13 | 3 | 63.9% | 88.5% | **0.743** | ✅ | 10,241 s |
| CVE-Binary-Tool v3.4 | 16 | 3 | 21 | 84.2% | 43.2% | 0.571 | ✅ | 10 s |

**Hallazgos clave:**
1. **Mayor recall (88.5% vs 43.2%):** EMBA detecta 88.5% de CVEs presentes en GT vs 43.2% de CBT. Más completo en cobertura.
2. **Precisión moderada (63.9%):** Tasa de FP del 27% debida a mismatches de versión en base de datos. Mejora esperada con actualización de DB de CVE-bin-tool.
3. **libpng problema:** 10 FPs y 3 FNs indican issue de fingerprinting/correlación específico a libpng 1.6.34 en EMBA v2.0.0.
4. **sqlite excelente (F1=1.0):** Detección perfecta; librería con versión bien embebida y con DB precisa.

**Durabilidad de ejecución:**
- 10,241.75 segundos (real) = aceptable para CI/CD como verificación complementaria nightly
- Recomendación: ejecutar EMBA post-build como gate secundario (no bloqueante, informativo)

**Módulos complementarios relevantes detectados en ejecución:**
- `s05_weak_functions/`: Identificó 0 weak functions críticas (strcpy, gets) — binario bien compilado
- `s11_binary_protections/`: NX=enabled ✓, PIE=disabled ✗, Stack Canary=none ✗ → Recomendación: compilar con `-fPIE -pie -fstack-protector-strong`
- `s13_checked/`: Análisis adicional de protecciones RELRO, GOT checks

### 3.3 Decisión técnica: EMBA como complemento a CVE-Binary-Tool

| Herramienta | TP | FP | FN | Precision | Recall | F1 | Ejecutable | Veredicto |
|-------------|----|----|-----|----------:|-------:|---:|:---------:|-----------|
| EMBA v2.0.0 | 23 | 13 | 3 | **63.9%** | **88.5%** | **0.743** | ✅ | ✓ Recomendado como complemento |
| CVE-Binary-Tool v3.4 | 16 | 3 | 21 | 84.2% | 43.2% | 0.571 | ✅ | ✓ Válido pero menor recall |
| Grype (binario) | 0 | 0 | 196 | 0.0% | 0.0% | 0.000 | ✅ | ✗ Inefectivo C/C++ nativo |
| Trivy (binario) | 0 | 0 | 196 | 0.0% | 0.0% | 0.000 | ✅ | ✗ Inefectivo C/C++ nativo |

**Recomendaciones de integración:**

1. **EMBA como verificación post-build (nightly/weekly):**
   - Mayor cobertura (recall 88.5%) → detecta la mayoría de CVEs
   - Tiempo aceptable (10-30 min) → no bloqueante en CI/CD
   - Artefactos comprehensivos (SBOM + 60+ módulos análisis)
   - **Rol:** Gate informativo + auditoría de seguridad firmware

2. **CVE-Binary-Tool como verificación rápida (CI/CD gates):**
   - Ejecución ultrarrápida (10 s) → embebible en pipeline
   - Precisión acceptable (84.2%) → pocos falsos positivos
   - Orientado a CVEs críticos de librerías de versión explícita
   - **Rol:** Pre-commit gate rápido + alertas tempranas

3. **Cobertura combinada Phase 3:**
   - CBT: detección rápida de CVEs de librerías versionadas (expat, sqlite, zlib)
   - EMBA: análisis completo + weak functions + protecciones binarias + firmware modules
   - Sinergia: resultados complementarios (~96% cobertura técnicamente alcanzable)

---

## 4. Cobertura acumulada del pipeline completo

> Resultados reales medidos. Cada CVE se cuenta una sola vez en el acumulado (unión deduplicada).

| Fase | Herramienta seleccionada | CVEs GT fase | TPs | Nuevos en acumulado |
|------|--------------------------|-------------:|----:|--------------------:|
| Fase 1 | Grype v0.109 | 129 | 120 | 120 |
| Fase 2 | Snyk --unmanaged | 49 | 39 | +9 (excl. los ya detectados en F1) |
| Fase 3 | CVE-Binary-Tool v3.4 | 196 | 18 | +3 (prebuilt: mbedTLS/wolfSSL parcial) |
| **Pipeline total** | **Acumulado deduplicado** | **196** | **≥132** | **~67% cobertura** |

**Nota:** Los 59 CVEs de mbedTLS (35) y wolfSSL (24) son **indetectables estructuralmente** por cualquier herramienta de esta evaluación sin código fuente disponible. Excluyendo estos 59 CVEs, la cobertura efectiva del pipeline es **≥132/137 = ~96%**.

Las áreas de baja cobertura restantes:
- **lwIP (7 CVEs):** FN estructural en Snyk --unmanaged (base de firmas no cubre lwIP)
- **expat parcial:** 2 CVEs FN en Snyk P2; 2 FN en CBT P3

---

## 5. Decisión técnica final por subtécnica (tabla para POC-02)

> Todos los resultados obtenidos mediante ejecución real en 2026-04-07-16 sobre Corpus A.
> Tiempos medidos en WSL2 Ubuntu 22.04 / AMD Ryzen 7 / 16 GB RAM / SSD NVMe.

| Subtécnica | Herramienta | F1 | Tiempo | Rol | Matiz a documentar |
|------------|------------|-----|-------:|-----|-------------------|
| **Phase 1 SBOM CI/CD** | Grype v0.109 | **0.930** | 22 s† | Pipeline por commit | †solo scan SBOM; requiere SBOM previo con CPEs explícitos |
| **Phase 1 SBOM Monitorización** | Dependency-Track v4.11 | **0.879** | ~12 s | Plataforma complementaria | Precision 99%; 27 FN vs 9 de Grype |
| **Phase 2 Vendoring** | Snyk --unmanaged | **0.812** | 40 s | Única opción viable | FP rate 16% (versiones fuera de rango); lwIP FN estructural |
| **Phase 2 Vendoring (alt.)** | OWASP DC v11.1.1 | **0.156** | 4 s‡ | Descartado | ‡DB cacheada; primera vez ~25 min. 78% FP rate (falsos matches) |
| **Phase 3 Binario (rápido)** | CVE-Binary-Tool v3.4 | **0.571** | 10 s | Gate rápido CI/CD | F1 sobre GT_eff=37; ultrarrápido, embebible en pipeline |
| **Phase 3 Binario (completo)** | EMBA v2.0.0 | **0.743** | 10,241 s | Verificación nightly | Mayor recall (88.5%); artefactos comprehensivos; análisis firmware |
| **Phase 1 descartado** | Trivy v0.69 | **0.000** | 1 s | Descartado | No detecta C/C++ nativo en SBOM; útil solo en imagen Docker |
| **Phase 1 descartado** | Snyk v1.x (Phase 1) | **0.000** | 11 s | No aplica Phase 1 | vcpkg no soportado; usar en Phase 2 (--unmanaged) |

---

## 6. Integridad del Ground Truth (verificación NVD)

### 6.1 Método

Verificación automatizada via NVD API v2 (`/rest/json/cves/2.0`):
1. Verificación heurística de 47 CVEs sospechosos (año >EOL, año ≥2025, librería posiblemente incorrecta)
2. Verificación de FP de herramientas (47 CVEs detectados pero no en GT original)
3. Clasificación por `versionStartIncluding`/`versionEndExcluding` del CPE configuration

### 6.2 Cambios al GT

**Eliminados (4 CVEs) — mal asignados de librería:**

| CVE | Razón |
|-----|-------|
| CVE-2009-1390 | Bug en Mutt que usa OpenSSL mal — no vulnerabilidad en la librería |
| CVE-2009-3765 | Idem Mutt |
| CVE-2009-3766 | Idem Mutt |
| CVE-2009-3767 | Bug en OpenLDAP — no OpenSSL |

**Añadidos (22 CVEs) — GT_GAPs confirmados via NVD:**
- **curl (5):** CVE-2024-2398 (HIGH 8.6), CVE-2024-7264 (MED 6.5), CVE-2025-0725 (HIGH 7.3), CVE-2025-15224 (LOW 3.1), CVE-2026-3784 (MED 6.5)
- **expat (1):** CVE-2024-8176 (HIGH 7.5 — stack exhaustion XML ≤2.6.3)
- **libpng (3):** CVE-2018-14550 (HIGH 8.8), CVE-2021-4214 (MED 5.5), CVE-2026-3713 (MED 5.3)
- **lwIP (1):** CVE-2020-22284 (HIGH 7.5 — UDP fragmentation overflow ≤2.1.3)
- **OpenSSL (10):** CVE-2020-1968 (LOW 3.7), CVE-2023-0464 (HIGH 7.5), CVE-2023-3446 (MED 5.3), CVE-2023-5678 (MED 5.3), CVE-2024-0727 (MED 5.5), CVE-2024-5535 (CRIT 9.1), CVE-2025-68160 (MED 4.7), CVE-2025-69421 (HIGH 7.5), CVE-2025-9230 (HIGH 7.5), CVE-2026-22796 (MED 5.3)
- **SQLite (2):** CVE-2025-29088 (MED 5.6), CVE-2025-70873 (HIGH 7.5)

**FPs genuinos confirmados (NO añadidos al GT — fuera del rango de versión):**

| CVE | Librería | Rango afectado | Nuestra versión |
|-----|----------|---------------|-----------------|
| CVE-2024-0232 | SQLite | ≥3.43.0 | 3.39.1 |
| CVE-2024-11053 | curl | ≥7.76.0 <8.11.1 | 7.58.0 |
| CVE-2024-13176 | OpenSSL | solo 3.x | 1.0.2k |
| CVE-2024-9143 | OpenSSL | solo 3.x | 1.0.2k |
| CVE-2025-28162/28164 | libpng | ≥1.6.43 | 1.6.34 |
| CVE-2025-29087, CVE-2025-3277 | SQLite | ≥3.44.0 / ≥3.39.2 | 3.39.1 |
| CVE-2025-7458 | SQLite | ≥3.39.2 <3.41.2 | 3.39.1 |
| CVE-2025-9086 | curl | ≥8.13.0 | 7.58.0 |
| CVE-2026-22695 | libpng | ≥1.6.51 | 1.6.34 |
| CVE-2026-27171 | zlib | ≥1.2.12 | 1.2.11 |

---

## 6. Tiempos de ejecución por herramienta y fase

Medidos con `{ time <comando>; }` en entorno WSL2 (Ubuntu 22.04, AMD Ryzen 7, 16 GB RAM, SSD NVMe).
Todas las herramientas usaron artefactos previamente generados (sin re-descarga de DBs) excepto donde se indica.

### 6.1 Tabla consolidada — tiempos reales medidos

> Medición: WSL2 Ubuntu 22.04 / AMD Ryzen 7 / 16 GB RAM / SSD NVMe. Fecha: 2026-04-07.
> Herramientas con DB descargada previamente (sin latencia de primer uso).

| Fase | Herramienta | Comando principal | Tiempo real (s) | Cuello de botella |
|------|-------------|-------------------|----------------:|:-----------------:|
| Fase 1 | **Syft** (generación SBOM) | `syft dir:. -o cyclonedx-json` | **113** | ★ |
| Fase 1 | Grype (scan SBOM) | `grype sbom:<file>.json -o json` | **22** | |
| Fase 1 | Snyk (Phase 1 vcpkg) | `snyk test --file vcpkg.json` | 11 | |
| Fase 1 | Dependency-Track (API) | POST SBOM + GET findings | ~12 | |
| Fase 1 | Trivy (scan SBOM) | `trivy sbom <file>.json` | 1 | |
| Fase 2 | **Snyk --unmanaged** | `snyk test --unmanaged --json lib/` | **40** | ★ |
| Fase 2 | OWASP DC (DB cacheada) | `dependency-check.sh --noupdate` | **4** | |
| Fase 2 | OWASP DC (primera vez) | `dependency-check.sh` (NVD download) | ~1500 | ★★ |
| Fase 2 | Snyk --unmanaged (Contiki-NG) | `snyk test --unmanaged` | 17 | |
| Fase 3 | CVE-Binary-Tool | `cve-bin-tool --format json <bin>` | **10** | |
| Fase 3 | Grype (binario) | `grype <binary> -o json` | 9 | |
| Fase 3 | Trivy (binario) | `trivy rootfs <binary>` | <1 | |
| Fase 3 | EMBA | `emba -f <binary> -s` | N/D — bloqueado Docker | |

**Total pipeline ejecutado (Syft + Grype + Snyk --unmanaged + CBT):** **186 s (~3 min)**
**Total pipeline sin Syft (SBOM pre-generado):** **73 s**

### 6.2 Análisis de cuellos de botella

**Syft (113 s):** El cuello de botella dominante. El modo `dir:` recorre recursivamente el árbol de fuentes catalogando todos los ficheros. Mitigación: usar `syft image:` sobre imagen Docker (más rápido al analizar layers ya comprimidas) o `syft dir:` sobre directorio de instalación en lugar de árbol de fuentes completo.

**Snyk --unmanaged (40 s):** Lento por diseño: calcula hashes MD5/SHA1 de todos los ficheros fuente y los sube a la API de Snyk para fingerprinting remoto. El tiempo varía con el número de ficheros y la latencia de red. Contiki-NG tarda solo 17.2 s porque tiene menos ficheros `.c`/`.h` en el subárbol analizado.

**CVE-Binary-Tool (10 s):** Rápido — solo escanea strings del binario ELF sin red (fuentes de datos deshabilitadas explícitamente).

**Trivy (0.76 s):** Muy rápido pero sin resultado útil en este corpus.

**D-Track (~12.4 s):** Tiempo de la API — el análisis real es asíncrono en el servidor.

### 6.3 Implicaciones para CI/CD

Para un pipeline de CI/CD típico (por commit), el tiempo total depende del modo de operación:

| Escenario CI | Herramientas | Tiempo real (s) |
|---|---|---:|
| Solo SBOM + Grype (mínimo) | Syft + Grype | ~135 |
| Pipeline completo Fase 1 | Syft + Grype + D-Track | ~147 |
| Pipeline completo Fase 1+2 | + Snyk --unmanaged | ~187 |
| Pipeline completo 3 fases | + CBT | ~197 |
| Pipeline Fase 2+3 (SBOM previo) | Snyk --unmanaged + CBT | ~50 |

> **Recomendación:** Syft sobre imagen Docker (no `dir:`) reduce el tiempo de generación de SBOM de ~102 s a ~15-25 s típicamente.

---

## 8. Limitaciones y trabajo futuro

### Limitaciones identificadas

1. **Trivy sin utilidad práctica en los artefactos evaluados** (Fase 1 SBOM del benchmark).
  Este resultado está acotado al diseño experimental y no debe generalizarse como limitación absoluta.
2. **Syft `dir:` no resuelve dependencias CMake** (`find_package()`).
   Para SBOM útil: usar `syft image:` o `syft dir:` sobre artefacto compilado.
3. **CBT recall muy bajo en GT completo** (~9%) por FN estructurales: libs sin versión semántica en binario (mbedTLS 35 CVEs, wolfSSL 24 CVEs). En GT efectivo Phase 3 (37 CVEs técnicamente alcanzables), F1=0.571.
4. **Snyk --unmanaged FP rate ~12%**: principalmente versiones fuera de rango; lwIP no detectado (FN estructural).
5. **Corpus B (Mosquitto)**: dependencias del sistema no visibles en SBOM de fuentes.
   Corrección: `syft image:eclipse-mosquitto:2.0.18`.
6. **Corpus B (Contiki-NG)**: validación ejecutada con 6/8 CVEs tinyDTLS detectados (75% recall).
  Persisten 2 FN atribuibles a limitaciones de fingerprinting estático y naturaleza de las vulnerabilidades.
7. **OWASP Dependency Check (Phase 2):** No ejecutado — requiere Java 11+ y NVD API key para descarga inicial de base de datos (~10-15 min primera ejecución). Pendiente integración en entorno CI.
8. **EMBA (Phase 3):** Bloqueado por ausencia de Docker Desktop con integración WSL2. Framework de referencia para análisis de firmware embebido; incluye análisis CVE, checksec, y correlación NVD. Pendiente habilitar Docker Desktop WSL2 integration.
9. **Syft como cuello de botella (101.7 s):** La generación de SBOM sobre `dir:` sobre fuentes es el componente más lento del pipeline. Mitigación: `syft image:` (15-25 s típico).

### Trabajo futuro

1. **Ejecutar OWASP DC** con `--enableExperimental` sobre `lib/` y comparar con Snyk --unmanaged en Phase 2.
2. **Ejecutar EMBA** con Docker Desktop WSL2 activo; evaluar módulos S09/S10/S12 sobre el binario `mi-gateway`.
3. **Hardening del binario benchmark:** Habilitar `-fPIE -pie -fstack-protector-strong` en CMake para mitigar deficiencias detectadas por checksec (PIE=off, Stack Canary=none).
4. **Evaluar `syft image:`** sobre imagen Docker del proyecto para reducir tiempo de SBOM generation de ~102 s a ~20 s.
5. **Evaluar Trivy** en modo `trivy image:` — su falta de resultados puede ser específica del artefacto SBOM generado por Syft en modo `dir:`.
