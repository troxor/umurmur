#!/usr/bin/env bash
# Native and cross-platform CI build helper for .github/workflows/portability.yml
set -euo pipefail

PLATFORM="${1:?platform required (ubuntu|macos|freebsd|openbsd|netbsd)}"
SSL="${2:?SSL backend required (openssl|mbedtls|gnutls)}"

ROOT="$(cd "$(dirname "$0")/../.." && pwd -P)"
cd "$ROOT"

CMAKE_SSL="$SSL"
CMAKE_EXTRA=()

as_root() {
  if [ "$(id -u)" -eq 0 ]; then
    "$@"
  elif command -v doas >/dev/null 2>&1 && [ -f /etc/doas.conf ]; then
    doas "$@"
  else
    su root -c "$(printf '%q ' "$@")"
  fi
}

mbedtls_major_version() {
  local from_pkg=0 from_hdr=0 header
  if command -v pkg-config >/dev/null 2>&1 && pkg-config --exists mbedtls 2>/dev/null; then
    from_pkg="$(pkg-config --modversion mbedtls | cut -d. -f1)"
    from_pkg="${from_pkg:-0}"
  fi
  for header in \
    /usr/include/mbedtls/build_info.h \
    /usr/include/mbedtls/version.h \
    /opt/homebrew/include/mbedtls/build_info.h \
    /opt/homebrew/include/mbedtls/version.h \
    /usr/local/include/mbedtls/build_info.h \
    /usr/pkg/include/mbedtls/build_info.h \
    /usr/pkg/include/mbedtls/version.h; do
    if [[ -f "$header" ]]; then
      from_hdr="$(awk '/MBEDTLS_VERSION_MAJOR/{gsub(/[^0-9]/, "", $3); print $3; exit}' "$header")"
      from_hdr="${from_hdr:-0}"
      break
    fi
  done
  if [[ "$from_hdr" -ge "$from_pkg" ]]; then
    echo "$from_hdr"
  else
    echo "$from_pkg"
  fi
}

resolve_cmake_ssl() {
  CMAKE_SSL="$SSL"
  if [[ "$SSL" != mbedtls ]]; then
    return
  fi
  # FreeBSD mbedtls3 port is still 3.x (slotted).
  if [[ "$PLATFORM" == freebsd ]]; then
    CMAKE_EXTRA+=(-DMbedTLS_SLOT=mbedtls3)
    return
  fi
  if [[ "$(mbedtls_major_version)" -ge 4 ]]; then
    CMAKE_SSL=mbedtls4
  fi
}

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
    openssl) brew install openssl@3 ;;
    mbedtls) brew install mbedtls ;;
    gnutls) brew install gnutls nettle ;;
    *) echo "unknown SSL backend: $SSL" >&2; exit 1 ;;
  esac
  if [[ "$SSL" == openssl ]]; then
    export OPENSSL_ROOT_DIR="$(brew --prefix openssl@3)"
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
  export PKG_PATH="https://cdn.openbsd.org/pub/OpenBSD/$(uname -r)/packages/$(arch -s)/"
  as_root pkg_add -U cmake gmake libconfig protobuf-c
  case "$SSL" in
    openssl) ;;
    mbedtls) as_root pkg_add -U mbedtls ;;
    gnutls) as_root pkg_add -U gnutls ;;
    *) echo "unknown SSL backend: $SSL" >&2; exit 1 ;;
  esac
}

install_netbsd() {
  export PKG_PATH="https://cdn.NetBSD.org/pub/pkgsrc/packages/NetBSD/$(uname -m)/$(uname -r | cut -f1,2 -d.)/$(uname -m)/All"
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
    -DSSL="$CMAKE_SSL"
    -DCMAKE_BUILD_TYPE=Debug
    -DUSE_SHAREDMEMORY_API=ON
  )
  if [[ -n "$make_prog" ]]; then
    cmake_args+=(-DCMAKE_MAKE_PROGRAM="$make_prog" -G "Unix Makefiles")
  fi
  if ((${#CMAKE_EXTRA[@]} > 0)); then
    cmake_args+=("${CMAKE_EXTRA[@]}")
  fi

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

resolve_cmake_ssl
build_and_test
