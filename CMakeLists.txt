cmake_minimum_required(VERSION 3.16)
project(mi-gateway-iot VERSION 1.0.0 LANGUAGES C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

# =============================================================================
# BENCHMARK NOTE: All library versions are intentionally OLD and VULNERABLE.
# DO NOT update them. They define the ground truth CVEs for SCA evaluation.
# See docs/ground_truth.csv for the full list of expected CVEs.
# =============================================================================

# -----------------------------------------------------------------------------
# Build options
# -----------------------------------------------------------------------------
option(BUILD_ARM   "Cross-compile for ARM Cortex-M (requires arm-none-eabi-gcc)" OFF)
option(BUILD_SBOM  "Generate CycloneDX SBOM after build (requires Syft)"         OFF)

if(BUILD_ARM)
    set(CMAKE_C_COMPILER    arm-none-eabi-gcc)
    set(CMAKE_CXX_COMPILER  arm-none-eabi-g++)
    set(CMAKE_C_FLAGS       "${CMAKE_C_FLAGS} -mcpu=cortex-m4 -mthumb -mfpu=fpv4-sp-d16 -mfloat-abi=hard")
    set(CMAKE_EXE_LINKER_FLAGS "--specs=nosys.specs --specs=nano.specs")
    message(STATUS "[BENCHMARK] Cross-compiling for ARM Cortex-M4")
else()
    message(STATUS "[BENCHMARK] Compiling for host (x86_64)")
endif()

# -----------------------------------------------------------------------------
# Fase 2+3: librerías copiadas como código fuente en lib/
# Vulnerabilidades: ver ground_truth.csv, columna "inclusion_type=source"
# -----------------------------------------------------------------------------

# zlib 1.2.11 — CVE-2022-37434, CVE-2018-25032, CVE-2023-45853
# SOURCE: https://github.com/madler/zlib/releases/tag/v1.2.11
set(ZLIB_VERSION "1.2.11" CACHE STRING "zlib version (BENCHMARK: do not change)")
if(EXISTS "${CMAKE_SOURCE_DIR}/lib/zlib-${ZLIB_VERSION}/CMakeLists.txt")
    set(SKIP_INSTALL_ALL ON)
    add_subdirectory(lib/zlib-${ZLIB_VERSION} zlib_build EXCLUDE_FROM_ALL)
    message(STATUS "[BENCHMARK] zlib ${ZLIB_VERSION} — CVE-2022-37434, CVE-2018-25032, CVE-2023-45853")
else()
    message(WARNING "[BENCHMARK] lib/zlib-${ZLIB_VERSION} not found. Run scripts/setup.sh first.")
endif()

# libpng 1.6.34 — CVE-2018-13785, CVE-2019-7317
# SOURCE: https://github.com/pnggroup/libpng/releases/tag/v1.6.34
set(LIBPNG_VERSION "1.6.34" CACHE STRING "libpng version (BENCHMARK: do not change)")
if(EXISTS "${CMAKE_SOURCE_DIR}/lib/libpng-${LIBPNG_VERSION}/CMakeLists.txt")
    set(PNG_SHARED OFF CACHE BOOL "" FORCE)
    set(PNG_TESTS  OFF CACHE BOOL "" FORCE)
    add_subdirectory(lib/libpng-${LIBPNG_VERSION} libpng_build EXCLUDE_FROM_ALL)
    message(STATUS "[BENCHMARK] libpng ${LIBPNG_VERSION} — CVE-2018-13785, CVE-2019-7317")
else()
    message(WARNING "[BENCHMARK] lib/libpng-${LIBPNG_VERSION} not found. Run scripts/setup.sh first.")
endif()

# lwIP 2.1.2 — AMNESIA:33: CVE-2020-17437 .. CVE-2020-17443
# SOURCE: https://github.com/lwip-tcpip/lwip/releases/tag/STABLE-2_1_2_RELEASE
set(LWIP_VERSION "2.1.2" CACHE STRING "lwIP version (BENCHMARK: do not change)")
if(EXISTS "${CMAKE_SOURCE_DIR}/lib/lwip-${LWIP_VERSION}/CMakeLists.txt")
    add_subdirectory(lib/lwip-${LWIP_VERSION} lwip_build EXCLUDE_FROM_ALL)
    message(STATUS "[BENCHMARK] lwIP ${LWIP_VERSION} — CVE-2020-17437..17443 (AMNESIA:33)")
else()
    message(WARNING "[BENCHMARK] lib/lwip-${LWIP_VERSION} not found. Run scripts/setup.sh first.")
endif()

# expat 2.4.6 — CVE-2022-25235, CVE-2022-25236, CVE-2022-25313, CVE-2022-25314, CVE-2022-25315
# SOURCE: https://github.com/libexpat/libexpat/releases/tag/R_2_4_6
set(EXPAT_VERSION "2.4.6" CACHE STRING "expat version (BENCHMARK: do not change)")
if(EXISTS "${CMAKE_SOURCE_DIR}/lib/expat-${EXPAT_VERSION}/CMakeLists.txt")
    set(EXPAT_BUILD_TOOLS    OFF CACHE BOOL "" FORCE)
    set(EXPAT_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
    set(EXPAT_BUILD_TESTS    OFF CACHE BOOL "" FORCE)
    set(EXPAT_SHARED_LIBS    OFF CACHE BOOL "" FORCE)
    add_subdirectory(lib/expat-${EXPAT_VERSION} expat_build EXCLUDE_FROM_ALL)
    message(STATUS "[BENCHMARK] expat ${EXPAT_VERSION} — CVE-2022-25235..25315")
else()
    message(WARNING "[BENCHMARK] lib/expat-${EXPAT_VERSION} not found. Run scripts/setup.sh first.")
endif()

# SQLite 3.39.1 (amalgamation) — CVE-2022-35737
# SOURCE: https://www.sqlite.org/2022/sqlite-amalgamation-3390100.zip
set(SQLITE_VERSION "3.39.1" CACHE STRING "SQLite version (BENCHMARK: do not change)")
if(EXISTS "${CMAKE_SOURCE_DIR}/lib/sqlite-${SQLITE_VERSION}/sqlite3.c")
    add_library(sqlite3 STATIC
        lib/sqlite-${SQLITE_VERSION}/sqlite3.c
    )
    target_include_directories(sqlite3 PUBLIC
        lib/sqlite-${SQLITE_VERSION}
    )
    message(STATUS "[BENCHMARK] SQLite ${SQLITE_VERSION} (amalgamation) — CVE-2022-35737")
else()
    message(WARNING "[BENCHMARK] lib/sqlite-${SQLITE_VERSION} not found. Run scripts/setup.sh first.")
endif()

# -----------------------------------------------------------------------------
# Fase 1+3: dependencias declaradas (para que Syft las incluya en el SBOM)
# curl 7.58.0 — CVE-2018-1000007, -1000120, -1000121, -1000122, -1000301
# OpenSSL 1.0.2k — CVE-2017-3735, CVE-2018-0737, CVE-2018-0739, CVE-2017-3737
# Nota: estas se buscan en el sistema; si no están instaladas, el SBOM
# las registra como dependencias declaradas igualmente via vcpkg.json
# -----------------------------------------------------------------------------
find_package(OpenSSL QUIET)
find_package(CURL QUIET)

if(OpenSSL_FOUND)
    message(STATUS "[BENCHMARK] OpenSSL encontrado: ${OPENSSL_VERSION} (esperado 1.0.2k para CVEs)")
endif()
if(CURL_FOUND)
    message(STATUS "[BENCHMARK] curl encontrado: ${CURL_VERSION_STRING} (esperado 7.58.0 para CVEs)")
endif()

# -----------------------------------------------------------------------------
# Ejecutable principal
# -----------------------------------------------------------------------------
add_executable(mi-gateway main.c)

target_include_directories(mi-gateway PRIVATE
    $<$<TARGET_EXISTS:zlibstatic>:${CMAKE_SOURCE_DIR}/lib/zlib-${ZLIB_VERSION}>
    $<$<TARGET_EXISTS:png_static>:${CMAKE_SOURCE_DIR}/lib/libpng-${LIBPNG_VERSION}>
    $<$<TARGET_EXISTS:png_static>:${CMAKE_BINARY_DIR}/libpng_build>
    $<$<TARGET_EXISTS:expat>:${CMAKE_SOURCE_DIR}/lib/expat-${EXPAT_VERSION}/lib>
    $<$<TARGET_EXISTS:sqlite3>:${CMAKE_SOURCE_DIR}/lib/sqlite-${SQLITE_VERSION}>
)

target_link_libraries(mi-gateway PRIVATE
    $<$<TARGET_EXISTS:zlibstatic>:zlibstatic>
    $<$<TARGET_EXISTS:png_static>:png_static>
    $<$<TARGET_EXISTS:expat>:expat>
    $<$<TARGET_EXISTS:sqlite3>:sqlite3>
    $<$<BOOL:${OpenSSL_FOUND}>:OpenSSL::SSL>
    $<$<BOOL:${CURL_FOUND}>:CURL::libcurl>
)

# -----------------------------------------------------------------------------
# Post-build: generación opcional de SBOM con Syft
# -----------------------------------------------------------------------------
if(BUILD_SBOM)
    find_program(SYFT_EXECUTABLE syft)
    if(SYFT_EXECUTABLE)
        add_custom_command(TARGET mi-gateway POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_SOURCE_DIR}/sbom
            COMMAND ${SYFT_EXECUTABLE} dir:${CMAKE_SOURCE_DIR}
                    --output cyclonedx-json=${CMAKE_SOURCE_DIR}/sbom/sbom-cyclonedx.json
                    --output spdx-json=${CMAKE_SOURCE_DIR}/sbom/sbom-spdx.json
            COMMENT "[BENCHMARK] Generando SBOM CycloneDX y SPDX con Syft..."
        )
        message(STATUS "[BENCHMARK] Syft encontrado — SBOM se generará en sbom/")
    else()
        message(WARNING "[BENCHMARK] Syft no encontrado. Instálalo: https://github.com/anchore/syft")
    endif()
endif()

# -----------------------------------------------------------------------------
# Instalar vcpkg.json para registrar versiones exactas (ayuda a Fase 1)
# -----------------------------------------------------------------------------
configure_file(
    ${CMAKE_SOURCE_DIR}/vcpkg.json.in
    ${CMAKE_SOURCE_DIR}/vcpkg.json
    @ONLY
)

message(STATUS "")
message(STATUS "=== BENCHMARK mi-gateway-iot configurado ===")
message(STATUS "  Ground truth: docs/ground_truth.csv")
message(STATUS "  Scripts:      scripts/")
message(STATUS "  Para ejecutar el benchmark completo: scripts/run_all.sh")
message(STATUS "============================================")
