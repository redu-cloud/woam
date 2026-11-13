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
# `by` must be the KERNEL's answer, and WOAM_ACTOR must NOT be able to overwrite it.
# An identity the subject supplies about itself is a claim; if it could sign a record as
# somebody else, the whole attribution layer would be decorative.
if any(r.get("by") == "smoke@test" for r in recs):
    bad.append("WOAM_ACTOR overwrote `by` - a self-declared identity is passing for evidence")
if not any(r.get("claims") == "smoke@test" for r in recs):
    bad.append("the caller's self-declared label was dropped instead of recorded as a claim")
if not any("auid=" in str(r.get("by", "")) for r in recs):
    bad.append("`by` does not carry the kernel login identity")
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
echo "[12] attribution (delegated to test/attribution.py, real kernel records)"
if python3 "$HERE/attribution.py" >"$WOAM_ROOT/.attrib.out" 2>&1; then
  ok "attribution suite ($(grep -oE '^[0-9]+ passed' "$WOAM_ROOT/.attrib.out") against captured audit records)"
else
  bad "attribution suite" "$(tail -12 "$WOAM_ROOT/.attrib.out")"
fi

echo
echo "[13] the audit surface degrades honestly on a box with no auditd"
rc=$(WOAM_AUDIT_LOG=/nonexistent/audit.log run audit-status)
t "audit-status exits non-zero when attribution is off" "$([ "$rc" = 1 ] && echo 0 || echo 1)" "got exit $rc"
t "and says attribution is OFF rather than staying quiet" "$(has 'ATTRIBUTION IS OFF')"
rc=$(WOAM_AUDIT_LOG=/nonexistent/audit.log run who /etc/hosts)
t "who exits non-zero rather than answering" "$([ "$rc" = 1 ] && echo 0 || echo 1)" "got exit $rc"
t "and never invents an answer" "$(hasnt 'AGENT/HUMAN')"
run audit-rules >/dev/null
t "audit-rules still prints the watches with no auditd installed" "$(has '-k woam')"
t "and never watches the whole filesystem" "$(hasnt '-w / -p')"
t "nor as a syscall rule on /" "$(hasnt 'dir=/ -F')"
t "and no -w watch, which the kernel checks on every syscall" "$(hasnt '-p wa -k')"

echo
echo "[13b] automatic sealing must not race the agent it is helping"
# Sealing is a systemd timer now, so seal and note can cross: the timer records
# "changed, WHY NOT RECORDED" while the agent is still working, rebaselines, and the
# agent's own `woam note` then finds nothing to attach to. The result is a permanent
# unexplained gap for a change somebody DID explain. Two mechanisms stop that, and
# both are asserted here.
python3 - "$WOAM_ROOT/baseline.json" <<'PY'
import json, sys
p = sys.argv[1]; b = json.load(open(p))
for g, gi in b.items():
    for sname, r in (gi.get("subs") or {}).items():
        if r.get("f"):
            r["f"].pop(sorted(r["f"])[0]); r["hash"] = "2" * 16; gi["hash"] = "2" * 16
            json.dump(b, open(p, "w")); print(g); raise SystemExit(0)
PY
DIRTY2=$(python3 -c "import json,sys;b=json.load(open(sys.argv[1]));print([g for g,v in b.items() if v.get('hash')=='2'*16][0])" "$WOAM_ROOT/baseline.json")
rc=$(run seal --grace 99999)
t "seal --grace exits 0" "$([ "$rc" = 0 ] && echo 0 || echo 1)" "$(out)"
# With attribution off there is no write timestamp, so nothing can be held and the
# group is sealed as before. Skipping instead would mean never sealing at all.
t "with attribution OFF, grace cannot hold and the change is still recorded" "$(has 'WHY NOT RECORDED')"
rc=$(run seal --grace notanumber)
t "a bad --grace value is rejected, not silently treated as 0" "$([ "$rc" = 2 ] && echo 0 || echo 1)" "got exit $rc"

# The crossover: a gap exists, then the agent explains the group.
GAPID2=$(run gaps >/dev/null; grep -oE '\b[0-9a-f]{6}\b' "$WOAM_ROOT/.out" | head -1)
run note "$DIRTY2" "explained after the timer already sealed it" >/dev/null
t "explaining a group closes the gap a seal left open" "$(has 'closed 1 open gap')"
run gaps >/dev/null
t "and the gap no longer shows as unexplained" "$(hasnt "$GAPID2")"
run log >/dev/null
t "history is not rewritten: a gap_closed record is appended" "$(has 'gap_closed')"
t "and it records that the explanation came via a note" "$(has '"via":"note"')"

echo
echo "[13c] a change made from OFF the machine can still be recorded ON it"
# The last hole: an agent that rotates a credential through an HTTPS API from its own
# laptop changes the machine and leaves nothing on it - no file moved, no command ran
# there, so no watch and no audit record could ever exist. Measured today, exactly that
# happened and `woam status` on the VM said "all groups recorded". The agent knows what it
# did, so it writes the record itself and syncs it.
export WOAM_CLAIMS="$WOAM_ROOT/claims.jsonl"
CLAIM=$("$WOAM" claim app "rotated the admin password from off-box" 2>/dev/null)
t "claim emits one JSON line" "$(echo "$CLAIM" | python3 -c 'import sys,json;json.loads(sys.stdin.readline());print()' >/dev/null 2>&1 && echo 0 || echo 1)" "$CLAIM"
t "and the operator's own machine keeps a copy" "$([ -s "$WOAM_CLAIMS" ] && echo 0 || echo 1)"
t "the claim is marked as remote-origin, never as evidence" \
  "$(echo "$CLAIM" | grep -q '"by_evidence":"claimed-remote"' && echo 0 || echo 1)"
t "and its actor is prefixed so it cannot read as an audited one" \
  "$(echo "$CLAIM" | grep -q '"by":"claimed:' && echo 0 || echo 1)"

echo "$CLAIM" | run accept >/dev/null
t "accept lands it on this machine" "$(has 'accepted a remote claim against app')"
run show app >/dev/null
t "and the reader is TOLD it is a claim, not evidence" "$(has 'CLAIMED from off this machine')"
t "marked distinctly from an audited record" "$(has '~ ')"

rc=$(echo 'not json' | run accept)
t "garbage on stdin is refused" "$([ "$rc" = 2 ] && echo 0 || echo 1)" "got exit $rc"
rc=$(echo '{"why":"x","group":"nope"}' | run accept)
t "a claim for an unknown group is refused" "$([ "$rc" = 2 ] && echo 0 || echo 1)" "got exit $rc"
# The sender cannot promote its own record: accept RE-STAMPS the evidence field.
echo '{"group":"app","why":"forged","by":"root(auid=0,ses=1)","by_evidence":"agent"}' | run accept >/dev/null
run log >/dev/null
t "a sender CANNOT forge audited-looking evidence" "$(hasnt '\"by_evidence\":\"agent\"')"

echo
echo "[14] the installer's ORDER, which a real first boot proved is not cosmetic"
# Measured on a fresh VM: with the baseline taken BEFORE the auditd install,
# installing auditd itself showed up as an unrecorded change and the first `woam` an
# agent ran on a brand-new machine exited 1 blaming it for woam's own installation.
# An agent whose first encounter with the tool is a false accusation ignores it after
# that, and everything else here is then worth nothing.
INST="$HERE/../install.sh"
L_AUDIT=$(grep -n 'apt-get .*install -y auditd' "$INST" | head -1 | cut -d: -f1)
L_BASE=$(grep -n '"\$DEST" baseline' "$INST" | head -1 | cut -d: -f1)
t "the installer installs auditd before it baselines" \
  "$([ -n "$L_AUDIT" ] && [ -n "$L_BASE" ] && [ "$L_AUDIT" -lt "$L_BASE" ] && echo 0 || echo 1)" \
  "auditd at line ${L_AUDIT:-none}, baseline at line ${L_BASE:-none}"
t "there is exactly one baseline call, so it cannot run early as well" \
  "$([ "$(grep -c '"\$DEST" baseline' "$INST")" = 2 ] && echo 0 || echo 1)" \
  "found $(grep -c '"\$DEST" baseline' "$INST") (expected 2: the writable branch and the sudo branch)"
t "the apt install is bounded by a lock timeout" "$(grep -q 'DPkg::Lock::Timeout' "$INST" && echo 0 || echo 1)"
t "and a failed auditd install never aborts the installer" \
  "$(grep -q 'auditd install failed, continuing without attribution' "$INST" && echo 0 || echo 1)"

echo
echo "[15] house style, checked mechanically because prose never holds"
# A documented no-em-dash rule was violated 4,237 times across 168 files in the
# repo this tool came from, by agents that had read the rule. One greppable
# character; the check takes a second and the document took none.
DASHES=$(cd "$HERE/.." && git ls-files 2>/dev/null | while read -r f; do
  case "$f" in *.png|*.jpg|*.ico|*.webp) continue;; esac
  grep -lP '\x{2014}' -- "$f" 2>/dev/null
done)
t "no em-dashes in tracked files" "$([ -z "$DASHES" ] && echo 0 || echo 1)" "$DASHES"

echo
echo "[16] the notice reaches a NON-INTERACTIVE ssh, and never corrupts stdout"
# The whole point. Measured 2026-08-05: the login banner was installed on a VM the
# entire time two agents worked it, and neither ever saw it, because /etc/profile.d is
# sourced by LOGIN shells and every agent drives a machine with `ssh host "command"`.
# One of them then published a wrong cause for an outage woam had recorded correctly.
NDIR="$(mktemp -d)"

# a) silent when there is nothing unexplained - a notice that always fires is noise,
#    and noise gets ignored, which is worse than not having it at all.
: > "$NDIR/changes.jsonl"
QUIET="$(WOAM_ROOT="$NDIR" python3 "$HERE/../woam" banner --notice 2>&1)"
t "notice is silent on a machine with nothing unexplained" "$([ -z "$QUIET" ] && echo 0 || echo 1)" "$QUIET"

# b) speaks when there IS something unexplained
printf '%s\n' '{"ts":"2026-01-01T00:00:00Z","v":1,"ev":"gap","id":"aaa111","group":"app","by":"ubuntu(auid=1000,ses=9)","by_evidence":"agent","what":["mod:env:/etc/redu-app/redu-app.env"],"files":1,"why":null,"closed":false}' > "$NDIR/changes.jsonl"
LOUD="$(WOAM_ROOT="$NDIR" python3 "$HERE/../woam" banner --notice 2>&1)"
case "$LOUD" in *UNEXPLAINED*) r=0;; *) r=1;; esac
t "notice names the unexplained change" "$r" "$LOUD"
case "$LOUD" in *"woam who"*) r=0;; *) r=1;; esac
t "notice tells the agent HOW to ask who changed it" "$r" "$LOUD"

# c) STDOUT MUST STAY EMPTY. An agent running `ssh host "cat file"` has to get the file
#    and nothing else; polluting stdout breaks real automation and gets this deleted.
SOUT="$(WOAM_ROOT="$NDIR" python3 "$HERE/../woam" banner --notice 2>/dev/null)"
t "notice writes NOTHING to stdout" "$([ -z "$SOUT" ] && echo 0 || echo 1)" "$SOUT"

# e) a FORCED command (a platform certificate's force-command) is not an agent's shell: nothing there can act on
#    the notice, and on redu it landed in an audit record (2026-10-11). Silent there, still loud for `ssh host "cmd"`.
FORCED="$(SSH_ORIGINAL_COMMAND='redeploy 0123' WOAM_ROOT="$NDIR" python3 "$HERE/../woam" banner --notice 2>&1)"
t "notice is silent in a forced-command session" "$([ -z "$FORCED" ] && echo 0 || echo 1)" "$FORCED"
AGENT="$(env -u SSH_ORIGINAL_COMMAND WOAM_ROOT="$NDIR" python3 "$HERE/../woam" banner --notice 2>&1)"
case "$AGENT" in *UNEXPLAINED*) r=0;; *) r=1;; esac
t "notice still speaks in an agent's ssh session" "$r" "$AGENT"

# d) the installer must place it ABOVE Ubuntu's non-interactive guard, or it is dead code
grep -q 'woam banner --notice' "$HERE/../install.sh"
t "installer wires the notice into ~/.bashrc" "$?" ""
rm -rf "$NDIR"

echo
echo "[13] an unprivileged write says HOW to fix it, not just what broke"
# The journal is root-owned on a real machine, so `woam note` as a normal user hits
# this path. It used to raise a bare PermissionError. Measured on a redu deploy
# 2026-08-16: an agent hit it, wrote "needs sudo" into its own notes, and never used
# the journal again. The login banner TELLS agents to record what they did, so the
# command it points them at must answer with an instruction, not a diagnosis.
RODIR="$(mktemp -d)/redu"
mkdir -p "$RODIR" && chmod 0555 "$RODIR"
ROOUT="$(WOAM_ROOT="$RODIR" python3 "$HERE/../woam" note app "a change" 2>&1)"; RORC=$?
chmod 0755 "$RODIR" 2>/dev/null; rm -rf "$(dirname "$RODIR")"
if [ "$(id -u)" = "0" ]; then
  echo "  skipped (running as root, the unprivileged path cannot be reached)"
else
  t "an unwritable journal exits 1" "$([ "$RORC" = 1 ] && echo 0 || echo 1)" "got exit $RORC"
  t "names the exact command to re-run" "$(printf '%s' "$ROOUT" | grep -qF 'sudo woam note app' && echo 0 || echo 1)" "$ROOUT"
  t "quotes the reason so it can be pasted back" "$(printf '%s' "$ROOUT" | grep -qF "'a change'" && echo 0 || echo 1)" "$ROOUT"
  t "refuses to be read as clean" "$(printf '%s' "$ROOUT" | grep -qiF 'not' && printf '%s' "$ROOUT" | grep -qiF 'clean' && echo 0 || echo 1)" "$ROOUT"
  t "leads with the instruction, not the exception type" "$(printf '%s' "$ROOUT" | grep -qF 'PermissionError' && echo 1 || echo 0)" "$ROOUT"
fi

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
