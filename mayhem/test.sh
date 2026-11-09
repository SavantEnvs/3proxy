#!/usr/bin/env bash
#
# mayhem/test.sh — RUN 3proxy's own regression suite (tests/run.py) against the binary mayhem/build.sh built.
# exit 0 = pass. EDIT per repo. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this. DELETE this file if the repo has no meaningful tests.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

BIN="$SRC/mayhem/build/oracle/3proxy"
[ -x "$BIN" ] || { echo "missing $BIN: mayhem/build.sh did not build it" >&2; emit_ctrf "3proxy" 0 1 0; exit 1; }

passed=0; failed=0; skipped=0

# Known-answer probes. They run first and unconditionally, so a binary that does nothing (or exits 0
# at once) fails here even if the suite below prints nothing at all.
probe() {  # <name> <ok:0|1>
  if [ "$2" -eq 0 ]; then passed=$((passed + 1)); echo "ok   $1"; else failed=$((failed + 1)); echo "FAIL $1"; fi
}

help_out="$("$BIN" --help 2>&1 || true)"
case "$help_out" in *"3proxy"*"built with:"*) probe "--help names the program and its features" 0 ;; *) probe "--help names the program and its features" 1 ;; esac

work="$(mktemp -d)"
cat > "$work/kat.py" <<'PY'
import os, socket, subprocess, sys, time
binary, work = sys.argv[1], sys.argv[2]
s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()
cfg = os.path.join(work, "kat.cfg")
open(cfg, "w").write(f"""auth iponly
allow *
http reply * /gone 410 "X-Kat: yes"
http redir * /go 302 "http://example.org/target"
http echo * /echo**
httpsrv -p{port}
""")
p = subprocess.Popen([binary, cfg], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
def get(path):
    for _ in range(100):
        try:
            c = socket.create_connection(("127.0.0.1", port), timeout=5)
            break
        except OSError:
            time.sleep(0.1)
    else:
        return b""
    c.sendall(f"GET {path} HTTP/1.0\r\nHost: kat.example\r\n\r\n".encode())
    out = b""
    while True:
        d = c.recv(65536)
        if not d: break
        out += d
    c.close()
    return out
ok = True
def check(name, cond):
    global ok
    print(("ok   " if cond else "FAIL ") + name); ok = ok and cond
r = get("/gone")
check("reply rule answers 410 with its header", r.startswith(b"HTTP/1.0 410") and b"X-Kat: yes" in r)
r = get("/go")
check("redir rule answers 302 with its Location", r.startswith(b"HTTP/1.0 302") and b"Location: http://example.org/target" in r)
r = get("/echo/abc?q=1")
check("echo rule reports the request path", r.startswith(b"HTTP/1.") and b"/echo/abc" in r and b"kat.example" in r)
p.kill(); p.wait()
sys.exit(0 if ok else 1)
PY
if python3 "$work/kat.py" "$BIN" "$work"; then passed=$((passed + 3)); else failed=$((failed + 1)); fi
rm -rf "$work"

# The upstream regression suite; its last lines carry the counts.
out="$(python3 tests/run.py --bin "$BIN" 2>&1)"; rc=$?
printf '%s\n' "$out" | tail -n 40
summary="$(printf '%s\n' "$out" | grep -E '^cases: [0-9]+ +checks: [0-9]+ +passed: [0-9]+ +failed: [0-9]+ +skipped: [0-9]+' | tail -n 1)"
if [ -z "$summary" ]; then
  echo "tests/run.py printed no summary" >&2
  failed=$((failed + 1))
else
  p="$(sed -E 's/.*passed: ([0-9]+).*/\1/' <<<"$summary")"
  f="$(sed -E 's/.*failed: ([0-9]+).*/\1/' <<<"$summary")"
  s="$(sed -E 's/.*skipped: ([0-9]+).*/\1/' <<<"$summary")"
  # a healthy build passes hundreds of checks; far fewer means the binary ran almost nothing
  if [ "$p" -lt 300 ]; then f=$((f + 1)); echo "only $p checks passed" >&2; fi
  [ "$rc" -eq 0 ] || [ "$f" -gt 0 ] || f=1
  passed=$((passed + p)); failed=$((failed + f)); skipped=$((skipped + s))
fi

emit_ctrf "3proxy tests/run.py" "$passed" "$failed" "$skipped"
