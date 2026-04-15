/**
 * mi-gateway-iot — main.c
 *
 * BENCHMARK SCA — Proyecto sintético para evaluación de herramientas SCA
 * en entornos embebidos C/C++.
 *
 * PROPÓSITO: Este fichero instancia objetos de cada librería vulnerable para
 * que el linker las incluya en el binario ELF final. Así las herramientas de
 * Fase 3 (Grype dir:, CVE-Binary-Tool, Trivy fs) pueden detectarlas.
 *
 * NO ES CÓDIGO DE PRODUCCIÓN. La lógica de negocio es mínima e irrelevante.
 *
 * Librerías instanciadas (versiones vulnerables):
 *   - zlib       1.2.11   → CVE-2022-37434, CVE-2018-25032, CVE-2023-45853
 *   - libpng     1.6.34   → CVE-2018-13785, CVE-2019-7317
 *   - expat      2.4.6    → CVE-2022-25235..25315
 *   - sqlite     3.39.1   → CVE-2022-35737
 *   - (lwIP se inicializa por su propio CMake; no requiere llamada explícita)
 *
 * Ground truth completo: docs/ground_truth.csv
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---------------------------------------------------------------------------
 * zlib 1.2.11
 * CVEs esperados: CVE-2022-37434, CVE-2018-25032, CVE-2023-45853
 * --------------------------------------------------------------------------- */
#ifdef ZLIB_H
#  include <zlib.h>
#else
#  if __has_include("zlib.h")
#    include "zlib.h"
#    define HAS_ZLIB 1
#  endif
#endif

/* ---------------------------------------------------------------------------
 * libpng 1.6.34
 * CVEs esperados: CVE-2018-13785, CVE-2019-7317
 * --------------------------------------------------------------------------- */
#if __has_include("png.h")
#  include "png.h"
#  define HAS_LIBPNG 1
#endif

/* ---------------------------------------------------------------------------
 * expat 2.4.6
 * CVEs esperados: CVE-2022-25235, CVE-2022-25236, CVE-2022-25313,
 *                 CVE-2022-25314, CVE-2022-25315
 * --------------------------------------------------------------------------- */
#if __has_include("expat.h")
#  include "expat.h"
#  define HAS_EXPAT 1
#endif

/* ---------------------------------------------------------------------------
 * SQLite 3.39.1 (amalgamation)
 * CVEs esperados: CVE-2022-35737
 * --------------------------------------------------------------------------- */
#if __has_include("sqlite3.h")
#  include "sqlite3.h"
#  define HAS_SQLITE 1
#endif

/* ---------------------------------------------------------------------------
 * Funciones auxiliares mínimas para forzar linkado
 * Copilot: mantén estas funciones simples. No añadas lógica compleja.
 * --------------------------------------------------------------------------- */

/**
 * benchmark_init_zlib()
 * Inicializa y libera un z_stream para forzar linkado de zlib.
 * BENCHMARK: NO modifiques la versión de zlib — es deliberadamente 1.2.11
 */
static void benchmark_init_zlib(void) {
#ifdef HAS_ZLIB
    z_stream stream;
    memset(&stream, 0, sizeof(stream));
    int ret = deflateInit(&stream, Z_DEFAULT_COMPRESSION);
    if (ret == Z_OK) {
        deflateEnd(&stream);
    }
    printf("[BENCHMARK] zlib %s inicializado (esperado: 1.2.11)\n", ZLIB_VERSION);
#else
    printf("[BENCHMARK] zlib NO disponible — ejecuta scripts/setup.sh\n");
#endif
}

/**
 * benchmark_init_libpng()
 * Crea y destruye una estructura PNG para forzar linkado de libpng.
 * BENCHMARK: versión objetivo 1.6.34 (CVE-2018-13785, CVE-2019-7317)
 */
static void benchmark_init_libpng(void) {
#ifdef HAS_LIBPNG
    png_structp png_ptr = png_create_read_struct(
        PNG_LIBPNG_VER_STRING, NULL, NULL, NULL
    );
    if (png_ptr) {
        png_infop info_ptr = png_create_info_struct(png_ptr);
        png_destroy_read_struct(&png_ptr, info_ptr ? &info_ptr : NULL, NULL);
    }
    printf("[BENCHMARK] libpng %s inicializado (esperado: 1.6.34)\n",
           PNG_LIBPNG_VER_STRING);
#else
    printf("[BENCHMARK] libpng NO disponible — ejecuta scripts/setup.sh\n");
#endif
}

/**
 * benchmark_init_expat()
 * Crea y destruye un parser XML para forzar linkado de expat.
 * BENCHMARK: versión objetivo 2.4.6 (CVE-2022-25235..25315)
 */
static void benchmark_init_expat(void) {
#ifdef HAS_EXPAT
    XML_Parser parser = XML_ParserCreate(NULL);
    if (parser) {
        XML_ParserFree(parser);
    }
    printf("[BENCHMARK] expat %s inicializado (esperado: 2.4.6)\n",
           XML_ExpatVersion());
#else
    printf("[BENCHMARK] expat NO disponible — ejecuta scripts/setup.sh\n");
#endif
}

/**
 * benchmark_init_sqlite()
 * Abre una base de datos en memoria para forzar linkado de SQLite.
 * BENCHMARK: versión objetivo 3.39.1 (CVE-2022-35737)
 */
static void benchmark_init_sqlite(void) {
#ifdef HAS_SQLITE
    sqlite3 *db = NULL;
    int rc = sqlite3_open(":memory:", &db);
    if (rc == SQLITE_OK) {
        sqlite3_close(db);
    }
    printf("[BENCHMARK] SQLite %s inicializado (esperado: 3.39.1)\n",
           SQLITE_VERSION);
#else
    printf("[BENCHMARK] SQLite NO disponible — ejecuta scripts/setup.sh\n");
#endif
}

/* ---------------------------------------------------------------------------
 * main()
 * Copilot: mantén main() mínimo. Solo llama a las funciones de benchmark.
 * --------------------------------------------------------------------------- */
int main(int argc, char *argv[]) {
    (void)argc;
    (void)argv;

    printf("=============================================================\n");
    printf("  mi-gateway-iot — Benchmark SCA para entornos embebidos\n");
    printf("  Propósito: evaluar Grype, Snyk, CVE-Binary-Tool, FOSSA, ORT\n");
    printf("  Ground truth: docs/ground_truth.csv\n");
    printf("=============================================================\n\n");

    /* Inicialización de cada librería vulnerable */
    benchmark_init_zlib();
    benchmark_init_libpng();
    benchmark_init_expat();
    benchmark_init_sqlite();

    printf("\n[BENCHMARK] Binario listo para análisis SCA (Fase 3).\n");
    printf("[BENCHMARK] Ver scripts/run_phase3.sh para ejecutar las herramientas.\n");

    return EXIT_SUCCESS;
}
