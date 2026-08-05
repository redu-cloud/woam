#!/usr/bin/env bash
# woam smoke test. No network, no privileges, nothing installed.
#
# It runs against a throwaway WOAM_ROOT, so it never touches a real machine's
# record. The group paths themselves are absolute and are only ever READ.
#
# What it is actually protecting: the EXIT CODES. woam's entire enforcement is
# `woam status` returning non-zero, so a regression that makes it return 0 turns
# the tool into decoration without changing a word of its output. The two cases
# that must never report clean get their own assertions: a fresh install with no
# baseline, and an unrecorded change.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WOAM="$HERE/../woam"
export WOAM_ROOT
WOAM_ROOT="$(mktemp -d)"
export WOAM_ACTOR="smoke@test"
trap 'rm -rf "$WOAM_ROOT"' EXIT

pass=0; fail=0
ok()   { pass=$((pass+1)); printf '  ok   %s\n' "$1"; }
bad()  { fail=$((fail+1)); printf '  FAIL %s\n' "$1"; [ -n "${2:-}" ] && printf '       %s\n' "$2"; }
t()    { if [ "$2" = "0" ]; then ok "$1"; else bad "$1" "${3:-}"; fi; }

run() { "$WOAM" "$@" >"$WOAM_ROOT/.out" 2>"$WOAM_ROOT/.err"; echo $?; }
out() { cat "$WOAM_ROOT/.out" "$WOAM_ROOT/.err"; }
# Grep the files directly, never `out | grep -q`. With pipefail set, grep -q exits
# at the first match, cat takes SIGPIPE, and the pipeline reports failure - so the
# assertion fails precisely BECAUSE the string was found early. Cost an assertion
# that was reporting the opposite of the truth.
has()   { grep -qiF -- "$1" "$WOAM_ROOT/.out" "$WOAM_ROOT/.err" && echo 0 || echo 1; }
hasnt() { grep -qiF -- "$1" "$WOAM_ROOT/.out" "$WOAM_ROOT/.err" && echo 1 || echo 0; }

echo
echo "[1] a fresh install must NOT report clean"
rc=$(run status)
t "exits non-zero with no baseline" "$([ "$rc" = 1 ] && echo 0 || echo 1)" "got exit $rc"
t "says there is no baseline" "$(has 'NO BASELINE')"
t "does not say 'all groups recorded'" "$(hasnt 'all groups recorded')"
t "prints the banner" "$(has 'this cloud has its own rules')"

echo
echo "[2] baseline, then a clean machine"
rc=$(run baseline); t "baseline exits 0" "$([ "$rc" = 0 ] && echo 0 || echo 1)" "got exit $rc"
rc=$(run status);   t "clean status exits 0" "$([ "$rc" = 0 ] && echo 0 || echo 1)" "$(out | tail -5)"
t "reports all groups recorded" "$(has 'all groups recorded')"

echo
echo "[3] the map: every path lands in exactly one group"
rc=$(run groups); t "groups exits 0" "$([ "$rc" = 0 ] && echo 0 || echo 1)"
for g in app service network storage packages access kernel schedule host; do
  t "groups lists '$g'" "$(has "$g")"
done
run which /etc/fstab   >/dev/null; t "which /etc/fstab -> storage" "$(has storage)"
run which /etc/ssh/sshd_config >/dev/null; t "which sshd_config -> access" "$(has access)"
# The catch-all is the point: a path matching nothing must not vanish.
run which /nowhere/at/all/xyz >/dev/null; t "an unmatched path falls to host" "$(has host)"

echo
echo "[4] an unrecorded change must fail the gate"
# Simulate the filesystem having moved since the baseline by dropping one file
# from the recorded snapshot. This exercises the real diff/status path without
# writing to any system directory.
python3 - "$WOAM_ROOT/baseline.json" <<'PY'
import json, sys
p = sys.argv[1]
b = json.load(open(p))
for g in ("network", "kernel", "access", "packages", "service"):
    gi = b.get(g) or {}
    for sname, r in (gi.get("subs") or {}).items():
        if r.get("f"):
            r["f"].pop(sorted(r["f"])[0])
            r["hash"] = "0" * 16
            gi["hash"] = "0" * 16
            json.dump(b, open(p, "w"))
            print(g)
            raise SystemExit(0)
raise SystemExit("no baselined file to tamper with; cannot test the dirty path")
PY
DIRTY=$(python3 -c "import json,sys;b=json.load(open(sys.argv[1]));print([g for g,v in b.items() if v.get('hash')=='0'*16][0])" "$WOAM_ROOT/baseline.json")

rc=$(run status)
t "a changed group exits non-zero" "$([ "$rc" = 1 ] && echo 0 || echo 1)" "got exit $rc"
t "names the group ($DIRTY)" "$(has "$DIRTY")"
t "says the changes are unrecorded" "$(has 'UNRECORDED CHANGES')"
t "tells the agent the command to fix it" "$(has 'woam note')"

echo
echo "[5] recording it clears the gate"
rc=$(run note "$DIRTY" "smoke test: simulated change"); t "note exits 0" "$([ "$rc" = 0 ] && echo 0 || echo 1)" "$(out)"
rc=$(run status); t "status is clean again" "$([ "$rc" = 0 ] && echo 0 || echo 1)" "$(out | tail -5)"
run show "$DIRTY" >/dev/null; t "show surfaces the note" "$(has 'smoke test: simulated change')"
t "show prints probes as COMMANDS, not stored answers" "$(has 'these are commands, not stored answers')"

echo
echo "[6] bad input is rejected, not guessed at"
rc=$(run note nosuchgroup "x");  t "unknown group exits 2" "$([ "$rc" = 2 ] && echo 0 || echo 1)" "got exit $rc"
rc=$(run note app);              t "note with no reason exits 2" "$([ "$rc" = 2 ] && echo 0 || echo 1)" "got exit $rc"
rc=$(run show nosuchgroup);      t "show of unknown group exits 2" "$([ "$rc" = 2 ] && echo 0 || echo 1)" "got exit $rc"
rc=$(run nosuchcommand);         t "unknown command exits 2" "$([ "$rc" = 2 ] && echo 0 || echo 1)" "got exit $rc"
rc=$(run --help);                t "--help exits 0" "$([ "$rc" = 0 ] && echo 0 || echo 1)"

echo
echo "[7] seal: the unexplained change is still recorded"
rc=$(run seal); t "seal on a clean machine exits 0" "$([ "$rc" = 0 ] && echo 0 || echo 1)"
t "and says so plainly" "$(has 'nothing unrecorded')"

python3 - "$WOAM_ROOT/baseline.json" <<'PY'
import json, sys
p = sys.argv[1]; b = json.load(open(p))
for g, gi in b.items():
    for sname, r in (gi.get("subs") or {}).items():
        if r.get("f"):
            r["f"].pop(sorted(r["f"])[0]); r["hash"] = "1" * 16; gi["hash"] = "1" * 16
            json.dump(b, open(p, "w")); raise SystemExit(0)
PY
rc=$(run seal); t "seal records the change with no agent input" "$([ "$rc" = 0 ] && echo 0 || echo 1)" "$(out)"
t "marks the reason as MISSING, not invented" "$(has 'WHY NOT RECORDED')"
GAPID=$(out | grep -oE '^  [0-9a-f]{6}' | head -1 | tr -d ' ')
t "issues a closable id" "$([ -n "$GAPID" ] && echo 0 || echo 1)" "no id in: $(out | head -3)"

run gaps >/dev/null; t "the gap is listed" "$(has "$GAPID")"
rc=$(run why "$GAPID" "worked it out afterwards"); t "why closes it" "$([ "$rc" = 0 ] && echo 0 || echo 1)" "$(out)"
run gaps >/dev/null; t "gaps is empty once closed" "$(hasnt "$GAPID")"

echo
echo "[8] fix: correcting a wrong record is the reader's job"
rc=$(run fix app "the earlier note was wrong"); t "fix exits 0" "$([ "$rc" = 0 ] && echo 0 || echo 1)" "$(out)"
run log >/dev/null; t "the correction appends, it does not rewrite" "$(has 'the earlier note was wrong')"
t "and the original is still there" "$(has 'smoke test: simulated change')"

echo
echo "[9] the log format the atomicity guarantee depends on"
LOGBAD=$(python3 - "$WOAM_ROOT/changes.jsonl" <<'PY'
import json, sys
bad, recs = [], []
for i, ln in enumerate(open(sys.argv[1], encoding="utf-8"), 1):
    ln = ln.rstrip("\n")
    if not ln.strip():
        continue
    if len(ln.encode()) >= 4096:
        bad.append(f"line {i} is {len(ln.encode())} bytes, at or over PIPE_BUF")
    try:
        recs.append(json.loads(ln))
    except Exception as e:
        bad.append(f"line {i} is not valid JSON: {e}")
if not recs:
    bad.append("no records were written at all")
if any(r.get("by") != "smoke@test" for r in recs if r.get("by")):
    bad.append("WOAM_ACTOR was ignored; attribution would be wrong")
if not any(r.get("ev") == "gap_closed" for r in recs):
    bad.append("closing a gap did not append a gap_closed record")
print(";".join(bad))
PY
)
t "every record is one valid JSON line under PIPE_BUF" "$([ -z "$LOGBAD" ] && echo 0 || echo 1)" "$LOGBAD"

echo
echo "[10] secrets never enter the record"
SECRETBAD=$(python3 - "$WOAM_ROOT/baseline.json" <<'PY'
import json, re, sys
b = json.load(open(sys.argv[1]))
bad = []
for g, gi in b.items():
    for sname, r in (gi.get("subs") or {}).items():
        for path, keys in (r.get("k") or {}).items():
            for k, v in keys.items():
                if not re.fullmatch(r"[0-9a-f]{4,64}", str(v)):
                    bad.append(f"{g}/{sname} {path}:{k} stores {v!r}, not a digest")
print(";".join(bad[:5]))
PY
)
t "config values are stored as digests, never as values" "$([ -z "$SECRETBAD" ] && echo 0 || echo 1)" "$SECRETBAD"

echo
echo "[11] it is fast enough to actually be run"
START=$(date +%s%N)
run status >/dev/null
MS=$(( ($(date +%s%N) - START) / 1000000 ))
t "status completes in under 3s (${MS}ms)" "$([ "$MS" -lt 3000 ] && echo 0 || echo 1)" "${MS}ms"

echo
echo "[12] house style, checked mechanically because prose never holds"
# A documented no-em-dash rule was violated 4,237 times across 168 files in the
# repo this tool came from, by agents that had read the rule. One greppable
# character; the check takes a second and the document took none.
DASHES=$(cd "$HERE/.." && git ls-files 2>/dev/null | while read -r f; do
  case "$f" in *.png|*.jpg|*.ico|*.webp) continue;; esac
  grep -lP '\x{2014}' -- "$f" 2>/dev/null
done)
t "no em-dashes in tracked files" "$([ -z "$DASHES" ] && echo 0 || echo 1)" "$DASHES"

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
