#!/usr/bin/env bash
# =============================================================================
# setup.sh — Descarga las librerías en versiones VULNERABLES para el benchmark
#
# BENCHMARK SCA: mi-gateway-iot
# Propósito: preparar el entorno con TPLs en versiones conocidamente vulnerables
#
# Uso:
#   ./scripts/setup.sh
#   ./scripts/setup.sh --clean   # elimina lib/ y vuelve a descargar
#
# Requisitos: curl, wget, tar, unzip, git
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
LIB_DIR="$ROOT_DIR/lib"

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info()    { echo -e "${BLUE}[INFO]${NC}    $*"; }
log_ok()      { echo -e "${GREEN}[OK]${NC}      $*"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC}    $*"; }
log_error()   { echo -e "${RED}[ERROR]${NC}   $*"; }
log_bench()   { echo -e "${YELLOW}[BENCHMARK]${NC} $*"; }

# -----------------------------------------------------------------------------
# Versiones FIJADAS — NO CAMBIAR (son el ground truth del benchmark)
# -----------------------------------------------------------------------------
ZLIB_VERSION="1.2.11"
LIBPNG_VERSION="1.6.34"
LWIP_VERSION="2.1.2"
EXPAT_VERSION="2.4.6"
SQLITE_VERSION="3390100"   # formato interno SQLite: 3.39.1 → 3390100
SQLITE_VERSION_HUMAN="3.39.1"
CURL_VERSION="7.58.0"
CURL_VERSION_UNDERSCORE="7_58_0"
OPENSSL_VERSION="1.0.2k"

# -----------------------------------------------------------------------------
# Parseo de argumentos
# -----------------------------------------------------------------------------
CLEAN=false
for arg in "$@"; do
    case $arg in
        --clean) CLEAN=true ;;
        --help)
            echo "Uso: $0 [--clean] [--help]"
            echo "  --clean   Elimina lib/ y descarga todo de nuevo"
            exit 0
            ;;
    esac
done

if [ "$CLEAN" = true ]; then
    log_warn "Modo --clean: eliminando $LIB_DIR ..."
    rm -rf "$LIB_DIR"
fi

mkdir -p "$LIB_DIR"

echo ""
echo "============================================================"
echo "  Benchmark SCA — Descarga de librerías vulnerables"
echo "  Directorio destino: $LIB_DIR"
echo "============================================================"
echo ""
log_bench "ATENCIÓN: Las versiones descargadas son INTENCIONALMENTE VULNERABLES."
log_bench "NO las uses en producción. Son exclusivamente para evaluación SCA."
echo ""

# -----------------------------------------------------------------------------
# Función auxiliar para descargar con reintentos
# -----------------------------------------------------------------------------
download_file() {
    local url="$1"
    local dest="$2"
    local description="$3"

    if [ -f "$dest" ]; then
        log_ok "$description ya descargado"
        return 0
    fi

    log_info "Descargando $description ..."
    if command -v wget &>/dev/null; then
        wget -q --show-progress -O "$dest" "$url" || {
            log_error "Error descargando $url"
            return 1
        }
    elif command -v curl &>/dev/null; then
        curl -L --progress-bar -o "$dest" "$url" || {
            log_error "Error descargando $url"
            return 1
        }
    else
        log_error "Ni wget ni curl disponibles. Instala uno de los dos."
        exit 1
    fi
    log_ok "$description descargado"
}

# -----------------------------------------------------------------------------
# 1. zlib 1.2.11
#    CVEs: CVE-2022-37434, CVE-2018-25032, CVE-2023-45853
# -----------------------------------------------------------------------------
ZLIB_DIR="$LIB_DIR/zlib-${ZLIB_VERSION}"
ZLIB_TAR="$LIB_DIR/zlib-${ZLIB_VERSION}.tar.gz"
ZLIB_URL="https://github.com/madler/zlib/archive/refs/tags/v${ZLIB_VERSION}.tar.gz"

if [ ! -d "$ZLIB_DIR" ]; then
    download_file "$ZLIB_URL" "$ZLIB_TAR" "zlib ${ZLIB_VERSION}"
    tar -xzf "$ZLIB_TAR" -C "$LIB_DIR"
    rm -f "$ZLIB_TAR"
    log_bench "zlib ${ZLIB_VERSION} extraído → CVE-2022-37434, CVE-2018-25032, CVE-2023-45853"
else
    log_ok "zlib ${ZLIB_VERSION} ya existe en $ZLIB_DIR"
fi

# -----------------------------------------------------------------------------
# 2. libpng 1.6.34
#    CVEs: CVE-2018-13785, CVE-2019-7317
# -----------------------------------------------------------------------------
LIBPNG_DIR="$LIB_DIR/libpng-${LIBPNG_VERSION}"
LIBPNG_TAR="$LIB_DIR/libpng-${LIBPNG_VERSION}.tar.gz"
LIBPNG_URL="https://github.com/pnggroup/libpng/archive/refs/tags/v${LIBPNG_VERSION}.tar.gz"

if [ ! -d "$LIBPNG_DIR" ]; then
    download_file "$LIBPNG_URL" "$LIBPNG_TAR" "libpng ${LIBPNG_VERSION}"
    tar -xzf "$LIBPNG_TAR" -C "$LIB_DIR"
    rm -f "$LIBPNG_TAR"
    log_bench "libpng ${LIBPNG_VERSION} extraído → CVE-2018-13785, CVE-2019-7317"
else
    log_ok "libpng ${LIBPNG_VERSION} ya existe en $LIBPNG_DIR"
fi

# -----------------------------------------------------------------------------
# 3. lwIP 2.1.2
#    CVEs: CVE-2020-17437, CVE-2020-17439, CVE-2020-17440,
#          CVE-2020-17441, CVE-2020-17442, CVE-2020-17443  (AMNESIA:33)
# -----------------------------------------------------------------------------
LWIP_DIR="$LIB_DIR/lwip-${LWIP_VERSION}"
LWIP_URL="https://github.com/lwip-tcpip/lwip/archive/refs/tags/STABLE-2_1_2_RELEASE.tar.gz"
LWIP_TAR="$LIB_DIR/lwip-${LWIP_VERSION}.tar.gz"

if [ ! -d "$LWIP_DIR" ]; then
    download_file "$LWIP_URL" "$LWIP_TAR" "lwIP ${LWIP_VERSION}"
    mkdir -p "$LWIP_DIR"
    tar -xzf "$LWIP_TAR" -C "$LIB_DIR" --strip-components=1 \
        --one-top-level="lwip-${LWIP_VERSION}" || \
    tar -xzf "$LWIP_TAR" -C "$LIB_DIR"
    rm -f "$LWIP_TAR"
    log_bench "lwIP ${LWIP_VERSION} extraído → AMNESIA:33 (CVE-2020-17437..17443)"
else
    log_ok "lwIP ${LWIP_VERSION} ya existe en $LWIP_DIR"
fi

# -----------------------------------------------------------------------------
# 4. expat 2.4.6
#    CVEs: CVE-2022-25235, CVE-2022-25236, CVE-2022-25313,
#          CVE-2022-25314, CVE-2022-25315
# -----------------------------------------------------------------------------
EXPAT_DIR="$LIB_DIR/expat-${EXPAT_VERSION}"
EXPAT_TAR="$LIB_DIR/expat-${EXPAT_VERSION}.tar.gz"
EXPAT_VERSION_TAG=$(echo "$EXPAT_VERSION" | tr '.' '_')
EXPAT_URL="https://github.com/libexpat/libexpat/releases/download/R_${EXPAT_VERSION_TAG}/expat-${EXPAT_VERSION}.tar.gz"

if [ ! -d "$EXPAT_DIR" ]; then
    download_file "$EXPAT_URL" "$EXPAT_TAR" "expat ${EXPAT_VERSION}"
    tar -xzf "$EXPAT_TAR" -C "$LIB_DIR"
    rm -f "$EXPAT_TAR"
    log_bench "expat ${EXPAT_VERSION} extraído → CVE-2022-25235..25315"
else
    log_ok "expat ${EXPAT_VERSION} ya existe en $EXPAT_DIR"
fi

# -----------------------------------------------------------------------------
# 5. SQLite 3.39.1 (amalgamation)
#    CVEs: CVE-2022-35737
# -----------------------------------------------------------------------------
SQLITE_DIR="$LIB_DIR/sqlite-${SQLITE_VERSION_HUMAN}"
SQLITE_ZIP="$LIB_DIR/sqlite-amalgamation-${SQLITE_VERSION}.zip"
SQLITE_URL="https://www.sqlite.org/2022/sqlite-amalgamation-${SQLITE_VERSION}.zip"

if [ ! -d "$SQLITE_DIR" ]; then
    download_file "$SQLITE_URL" "$SQLITE_ZIP" "SQLite ${SQLITE_VERSION_HUMAN} amalgamation"
    mkdir -p "$SQLITE_DIR"
    if command -v unzip &>/dev/null; then
        unzip -q "$SQLITE_ZIP" -d "$LIB_DIR/sqlite_tmp"
        mv "$LIB_DIR/sqlite_tmp/sqlite-amalgamation-${SQLITE_VERSION}/"* "$SQLITE_DIR/"
        rm -rf "$LIB_DIR/sqlite_tmp"
    else
        log_warn "unzip no disponible. Extrayendo con python..."
        python3 -c "
import zipfile, shutil, os
with zipfile.ZipFile('$SQLITE_ZIP') as z:
    z.extractall('$LIB_DIR/sqlite_tmp')
inner = '$LIB_DIR/sqlite_tmp/sqlite-amalgamation-$SQLITE_VERSION'
for f in os.listdir(inner):
    shutil.move(os.path.join(inner, f), '$SQLITE_DIR/')
shutil.rmtree('$LIB_DIR/sqlite_tmp')
"
    fi
    rm -f "$SQLITE_ZIP"
    log_bench "SQLite ${SQLITE_VERSION_HUMAN} extraído → CVE-2022-35737"
else
    log_ok "SQLite ${SQLITE_VERSION_HUMAN} ya existe en $SQLITE_DIR"
fi

# -----------------------------------------------------------------------------
# 6. Verificación de curl y OpenSSL (sistema o aviso)
#    Estas se incluyen como dependencias declaradas (Fase 1)
# -----------------------------------------------------------------------------
echo ""
log_info "Verificando curl y OpenSSL en el sistema..."

CURL_SYSTEM_VERSION=$(curl --version 2>/dev/null | head -1 | awk '{print $2}' || echo "no encontrado")
OPENSSL_SYSTEM_VERSION=$(openssl version 2>/dev/null | awk '{print $2}' || echo "no encontrado")

if [[ "$CURL_SYSTEM_VERSION" == "no encontrado" ]]; then
    log_warn "curl no encontrado en el sistema. Para Fase 1, instala curl 7.58.0 o decláralo en vcpkg.json"
else
    log_info "curl en sistema: $CURL_SYSTEM_VERSION (benchmark target: 7.58.0)"
    if [[ "$CURL_SYSTEM_VERSION" != "7.58.0" ]]; then
        log_warn "La versión de curl en sistema ($CURL_SYSTEM_VERSION) NO coincide con el target del benchmark (7.58.0)."
        log_warn "Para Fase 1, usa el SBOM generado por Syft que leerá vcpkg.json con la versión correcta."
    fi
fi

if [[ "$OPENSSL_SYSTEM_VERSION" == "no encontrado" ]]; then
    log_warn "OpenSSL no encontrado en el sistema."
else
    log_info "OpenSSL en sistema: $OPENSSL_SYSTEM_VERSION (benchmark target: 1.0.2k)"
    if [[ "$OPENSSL_SYSTEM_VERSION" != "1.0.2k" ]]; then
        log_warn "La versión de OpenSSL en sistema ($OPENSSL_SYSTEM_VERSION) NO coincide con el target del benchmark (1.0.2k)."
    fi
fi

# -----------------------------------------------------------------------------
# Resumen final
# -----------------------------------------------------------------------------
echo ""
echo "============================================================"
echo "  Resumen de librerías descargadas"
echo "============================================================"
echo ""
for lib_dir in "$LIB_DIR"/*/; do
    lib_name=$(basename "$lib_dir")
    log_ok "$lib_name"
done

echo ""
log_bench "Ground truth completo en: docs/ground_truth.csv"
log_bench "Próximo paso: cmake -B build && cmake --build build"
log_bench "O directamente: scripts/run_all.sh"
echo ""
