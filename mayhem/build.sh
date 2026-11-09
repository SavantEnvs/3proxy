#!/usr/bin/env bash
#
# mayhem/build.sh — build 3proxy's fuzz harnesses and its regression-test binary.
#
# Runs in the commit image (mayhem/Dockerfile) as `mayhem` in /mayhem, offline and re-runnable.
#   1. oracle build : upstream Makefile.Linux, normal flags -> mayhem/build/oracle/3proxy (for test.sh)
#   2. fuzz build   : the same Makefile, sanitized (+ libFuzzer coverage) -> src/*.o, linked into the harnesses
#   3. harnesses    : mayhem/fuzz_*.c -> /mayhem/<name> (libFuzzer) and /mayhem/<name>-standalone (run-once)
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${SRC:=/mayhem}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

# Makefile.Linux builds the mail and FTP proxies only when asked; without these the services are stubs.
export MAILPROXY=true FTP=true

cd "$SRC"
BLD="$SRC/mayhem/build"
mkdir -p "$BLD/oracle" bin

# make reads CFLAGS/LDFLAGS from the environment (Makefile.Linux: `CFLAGS ?= -O3 -flto`, then `+=`),
# so these stay overridable but never carry upstream's default LTO.
build_objs() {  # <CFLAGS> <LDFLAGS> <make targets...>
  local cf="$1" lf="$2"; shift 2
  rm -f src/*.o bin/3proxy bin/3proxy_crypt
  cp Makefile.Linux src/Makefile.var
  CFLAGS="$cf" LDFLAGS="$lf" make -C src -j"$MAYHEM_JOBS" "$@"
}

# 1) the oracle build: normal flags, no sanitizers
build_objs "-O2 $COVERAGE_FLAGS" "$COVERAGE_FLAGS" ../bin/3proxy
cp bin/3proxy "$BLD/oracle/3proxy"

# 2) the project itself, sanitized and instrumented for libFuzzer
# -fno-sanitize=alignment: the `users` password table (hash.c) strides its records by
# sizeof(struct hashentry)+recsize-4, so entries are misaligned on x86 (harmless there) and would
# abort every input that defines a user before any later code runs. Every other check stays on.
FUZZ_CFLAGS="-O1 $SANITIZER_FLAGS $DEBUG_FLAGS -fno-sanitize=alignment -fsanitize=fuzzer-no-link"
FUZZ_LDFLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS"
build_objs "$FUZZ_CFLAGS" "$FUZZ_LDFLAGS" ../bin/3proxy

# The flags the Makefile resolved (feature defines, TLS/PCRE detection) and the libraries it links.
mk_print() {
  CFLAGS="$FUZZ_CFLAGS" LDFLAGS="$FUZZ_LDFLAGS" \
    make -s -C src -f Makefile.var -f ../mayhem/printflags.mk "$1"
}
RESOLVED_CFLAGS="$(mk_print print-cflags)"
LIBS="$(mk_print print-libs)"

# 3proxy.c carries main(); libFuzzer brings its own, so compile it once more with main renamed.
(cd src && $CC $RESOLVED_CFLAGS -Dmain=threeproxy_main -o "$BLD/3proxy_nomain.o" 3proxy.c)
OBJS="$(ls "$SRC"/src/*.o | grep -v '/3proxy\.o$' | tr '\n' ' ')"

$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c mayhem/lsan_off.cc -o "$BLD/lsan_off.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$BLD/standalone_main.o"

# 3) harnesses: <name> <source> [-D...]
build_harness() {
  local name="$1" source="$2"; shift 2
  $CC $RESOLVED_CFLAGS -I"$SRC/src" -I"$SRC/mayhem" "$@" "$source" -o "$BLD/$name.o"
  # shellcheck disable=SC2086
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$BLD/$name.o" "$BLD/3proxy_nomain.o" \
      $OBJS "$BLD/lsan_off.o" $LIBS -lm -o "$SRC/$name"
  # shellcheck disable=SC2086
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS "$BLD/standalone_main.o" "$BLD/$name.o" "$BLD/3proxy_nomain.o" \
      $OBJS "$BLD/lsan_off.o" $LIBS -lm -o "$SRC/$name-standalone"
}

build_harness fuzz_config  mayhem/fuzz_config.c
build_harness fuzz_httpsrv mayhem/fuzz_net.c -DFUZZ_HTTPSRV
build_harness fuzz_proxy   mayhem/fuzz_net.c -DFUZZ_PROXY
build_harness fuzz_socks   mayhem/fuzz_net.c -DFUZZ_SOCKS
build_harness fuzz_pop3p   mayhem/fuzz_net.c -DFUZZ_POP3P
build_harness fuzz_smtpp   mayhem/fuzz_net.c -DFUZZ_SMTPP
build_harness fuzz_imapp   mayhem/fuzz_net.c -DFUZZ_IMAPP
build_harness fuzz_ftppr   mayhem/fuzz_net.c -DFUZZ_FTPPR
