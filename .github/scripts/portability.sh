#!/usr/bin/env bash
# Native and cross-platform CI build helper for .github/workflows/portability.yml
set -euo pipefail

PLATFORM="${1:?platform required (ubuntu|macos|freebsd|openbsd|netbsd)}"
SSL="${2:?SSL backend required (openssl|mbedtls|gnutls)}"

ROOT="$(cd "$(dirname "$0")/../.." && pwd -P)"
cd "$ROOT"

CMAKE_EXTRA=()
if [[ "$PLATFORM" == freebsd && "$SSL" == mbedtls ]]; then
  # security/mbedtls3 installs headers/libs under the mbedtls3 slot.
  CMAKE_EXTRA+=(-DMbedTLS_SLOT=mbedtls3)
fi

install_ubuntu() {
  sudo apt-get update
  sudo apt-get install -y --no-install-recommends \
    build-essential cmake pkg-config libconfig-dev libprotobuf-c-dev
  case "$SSL" in
    openssl) sudo apt-get install -y --no-install-recommends libssl-dev ;;
    mbedtls) sudo apt-get install -y --no-install-recommends libmbedtls-dev ;;
    gnutls)
      sudo apt-get install -y --no-install-recommends libgnutls28-dev nettle-dev
      ;;
    *) echo "unknown SSL backend: $SSL" >&2; exit 1 ;;
  esac
}

install_macos() {
  brew install cmake libconfig protobuf-c
  case "$SSL" in
    openssl) brew install openssl ;;
    mbedtls) brew install mbedtls ;;
    gnutls) brew install gnutls nettle ;;
    *) echo "unknown SSL backend: $SSL" >&2; exit 1 ;;
  esac
  if [[ "$SSL" == openssl ]]; then
    export OPENSSL_ROOT_DIR="$(brew --prefix openssl)"
  fi
}

install_freebsd() {
  sudo pkg install -y cmake gmake pkgconf libconfig protobuf-c
  case "$SSL" in
    openssl) ;; # LibreSSL/OpenSSL in base + pkg provides cmake hints
    mbedtls) sudo pkg install -y mbedtls3 ;;
    gnutls) sudo pkg install -y gnutls ;;
    *) echo "unknown SSL backend: $SSL" >&2; exit 1 ;;
  esac
}

install_openbsd() {
  export PKG_PATH="https://cdn.openbsd.org/pub/OpenBSD/%m/%V/all/%a"
  doas pkg_add cmake gmake libconfig protobuf-c
  case "$SSL" in
    openssl) ;;
    mbedtls) doas pkg_add mbedtls ;;
    gnutls) doas pkg_add gnutls ;;
    *) echo "unknown SSL backend: $SSL" >&2; exit 1 ;;
  esac
}

install_netbsd() {
  export PKG_PATH="https://cdn.netbsd.org/pub/pkgsrc/packages/NetBSD/$(uname -m)/$(uname -r | cut -d. -f1)_$(uname -r | cut -d. -f2)/$(uname -m)/All"
  sudo pkgin -y update
  sudo pkgin -y install cmake gmake pkg-config libconfig protobuf-c
  case "$SSL" in
    openssl) ;;
    mbedtls) sudo pkgin -y install mbedtls ;;
    gnutls) sudo pkgin -y install gnutls ;;
    *) echo "unknown SSL backend: $SSL" >&2; exit 1 ;;
  esac
}

build_and_test() {
  local make_prog=""
  case "$PLATFORM" in
    freebsd|openbsd|netbsd) make_prog="$(command -v gmake)" ;;
  esac

  local -a cmake_args=(
    -S . -B build
    -DSSL="$SSL"
    -DCMAKE_BUILD_TYPE=Debug
    -DUSE_SHAREDMEMORY_API=ON
  )
  if [[ -n "$make_prog" ]]; then
    cmake_args+=(-DCMAKE_MAKE_PROGRAM="$make_prog" -G "Unix Makefiles")
  fi
  cmake_args+=("${CMAKE_EXTRA[@]}")

  cmake "${cmake_args[@]}"
  cmake --build build
  ctest --test-dir build --output-on-failure
}

case "$PLATFORM" in
  ubuntu) install_ubuntu ;;
  macos) install_macos ;;
  freebsd) install_freebsd ;;
  openbsd) install_openbsd ;;
  netbsd) install_netbsd ;;
  *) echo "unknown platform: $PLATFORM" >&2; exit 1 ;;
esac

build_and_test
