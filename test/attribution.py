#!/usr/bin/env python3
"""
The attribution layer, tested against REAL kernel records.

The fixtures in test/fixtures/ are not hand-written. They were captured from a live VM
running auditd 3.1.2, where two processes appended to the SAME FILE two seconds apart:

    /etc/redu-app/.attrib
      written by `sudo sh -c ...`        -> auid=1000  ses=218          (a login session)
      written by `systemd-run /bin/sh`   -> auid=4294967295  ses=...    (no login session)

That pair is the entire problem in one file. Snapshot/diff sees one changed file and
cannot say anything about who; it blamed whichever agent happened to be logged in. The
kernel recorded both writers exactly, and auid survived sudo in the first case.

Every assertion here is about NOT LYING:
  * an agent write is attributed to the agent,
  * a system write is attributed to the system and never charged to an agent,
  * an UNWATCHED path returns "unknown", never "system" - absence of a record is only
    evidence when we were actually looking,
  * with auditd absent, the layer says so instead of guessing.

Run: python3 test/attribution.py     (no root, no auditd, no network)
"""
import os
import re
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
FIX = HERE / "fixtures"

os.environ.setdefault("WOAM_ROOT", tempfile.mkdtemp())

_pass, _fail = 0, 0


def t(name, cond, extra=""):
    global _pass, _fail
    if cond:
        _pass += 1
        print(f"  ok   {name}")
    else:
        _fail += 1
        print(f"  FAIL {name}" + (f"\n       {extra}" if extra else ""))


def load(audit_log=None, rules=None):
    """Load woam as a module with the audit paths pointed at fixtures."""
    if audit_log is not None:
        os.environ["WOAM_AUDIT_LOG"] = str(audit_log)
    else:
        os.environ["WOAM_AUDIT_LOG"] = "/nonexistent/audit.log"
    os.environ["WOAM_AUDIT_RULES"] = str(rules) if rules else "/nonexistent/woam.rules"
    src = (HERE.parent / "woam").read_text().replace('if __name__ == "__main__":', "if False:")
    mod = type(sys)("woam_under_test")
    exec(compile(src, "woam", "exec"), mod.__dict__)
    return mod


RULES = Path(tempfile.mkdtemp()) / "woam.rules"
RULES.write_text("-w /etc/redu-app -p wa -k woam\n")
TARGET = "/etc/redu-app/.attrib"

print("\n[1] parsing real kernel records")
m = load(FIX / "audit-real.log", RULES)
evs = m.audit_writes()
t("both writes to the same file are parsed", len(evs) == 2, f"got {len(evs)}")
t("auid SURVIVES sudo (uid=0 but auid=1000)", evs[0]["auid"] == 1000 and not evs[0]["system"])
t("the systemd write carries the unset sentinel", evs[1]["auid"] == m.AUID_UNSET)
t("and is classified as system", evs[1]["system"] is True)
t("the PAM session id is captured", evs[0]["ses"] == 218)
t("the program is captured", evs[0]["comm"] == "sh" and evs[0]["exe"].endswith("dash"))
t("the syscall's success is captured", evs[0]["success"] == "yes")
t("nametype=PARENT is EXCLUDED, so a file write is not reported as a write to /etc",
  all("/etc/redu-app/" not in p or p != "/etc/redu-app/" for p in evs[0]["paths"])
  and evs[0]["paths"] == [TARGET], evs[0]["paths"])

print("\n[2] the verdict, which is what callers act on")
v, actors, hits = m.attribution_for([TARGET])
t("a login-session write makes it an AGENT change", v == "agent", f"got {v!r}")
t("and names the actor with auid + session", any("auid=1000" in a and "ses=218" in a for a in actors), str(actors))

m2 = load(FIX / "audit-system-only.log", RULES)
v2, a2, h2 = m2.attribution_for([TARGET])
t("a system-only write is SYSTEM, never charged to an agent", v2 == "system", f"got {v2!r}")
t("and reports no human actors", a2 == [], str(a2))

print("\n[3] the distinction that keeps it honest")
v3, _a, _h = m.attribution_for(["/etc/somewhere/not-watched"])
t("an UNWATCHED path is 'unwatched', NOT 'system'", v3 == "unwatched", f"got {v3!r}")
# This is the one that matters most. If absence of a record meant "the system did it",
# every path nobody thought to watch would be silently excused, and woam would go quiet
# exactly where it has no information.

norules = Path(tempfile.mkdtemp()) / "empty.rules"
norules.write_text("# no watches\n")
m4 = load(FIX / "audit-real.log", norules)
v4, _a, _h = m4.attribution_for([TARGET])
t("no watches loaded means 'unwatched', not a clean bill of health", v4 == "unwatched", f"got {v4!r}")

m5 = load(None, RULES)
ok, why = m5.audit_available()
t("with no audit log, audit_available() is False", ok is False)
t("and it says WHY", "auditd" in why or "no audit log" in why, why)
v5, _a, _h = m5.attribution_for([TARGET])
t("verdict is 'no-audit', not a guess", v5 == "no-audit", f"got {v5!r}")

print("\n[4] classify_dirty: the OS must not be reported as the agent's work")
dirty = {
    "app": {"since": "1970-01-01T00:00:00Z", "subs": [("env", 1)], "files": 1,
            "named": {"env": {"modified": [TARGET], "created": [], "removed": []}}},
}
agent, system = m2.classify_dirty({k: dict(v) for k, v in dirty.items()})   # system-only log
t("a group only the OS touched is NOT an unrecorded agent change", "app" not in agent, str(list(agent)))
t("it is reported separately as the system's work", "app" in system)

agent2, system2 = m.classify_dirty({k: dict(v) for k, v in dirty.items()})  # log with a human write
t("a group an agent touched IS an unrecorded change", "app" in agent2)
t("and carries the actor through to the report", agent2["app"].get("actors"), str(agent2["app"].get("actors")))

agent3, system3 = m5.classify_dirty({k: dict(v) for k, v in dirty.items()})  # no auditd
t("with attribution OFF nothing is excused as 'the system did it'",
  "app" in agent3 and system3 == {}, f"agent={list(agent3)} system={list(system3)}")

print("\n[5] the watches are generated from GROUPS, so they cannot drift")
rules = m.audit_rules_text()
_rl = [l for l in rules.splitlines() if l and not l.startswith("#")]
_rules = [l for l in _rl if l != "-c"]
t("every rule is an exit rule (no -w: the kernel checks those on EVERY syscall)",
  all(l.startswith("-a always,exit ") for l in _rules),
  str([l for l in _rules if not l.startswith("-a always,exit ")][:2]))
# Measured 13 Nov 2026: a rule without -S cost +38% on a syscall-bound loop, scoped +15%.
t("EVERY rule names its syscalls", all(" -S " in l for l in _rules),
  str([l for l in _rules if " -S " not in l][:1]))
t("every rule carries exactly one of the two keys",
  all(m._rule_ident(l) and m._rule_ident(l)[0] in (m.AUDIT_KEY, m.AUDIT_CMD_KEY) for l in _rules))
# The boot load is one auditctl pass; without -c the first missing path stops it.
t("-c comes before every rule, so one refused rule cannot stop the boot load",
  "-c" in _rl and all(not l.startswith("-a ") for l in _rl[:_rl.index("-c")]))

# The exec rules are what answer "did an AGENT do this" for state with no file behind it.
# auid!=unset must be in the KERNEL predicate: it is what stops a daemon's own work from
# being recorded at all, which is both the correctness property and the volume control.
_ex = [l for l in _rules if m._rule_ident(l)[0] == m.AUDIT_CMD_KEY]
t("exec rules exist for the state-changing commands", len(_ex) > 0, str(len(_ex)))
t("EVERY exec rule filters auid!=unset in the kernel",
  all("-F auid!=unset" in l for l in _ex),
  str([l for l in _ex if "-F auid!=unset" not in l][:1]))
t("every exec rule is -S execve,execveat on a resolved absolute path",
  all(f"-S {m.AUDIT_EXEC_SYSCALLS} " in l and re.search(r"-F path=/", l) for l in _ex))
t("exec rules carry their own key, so they never mix with file writes",
  all(f"-k {m.AUDIT_CMD_KEY}" in l for l in _ex))

_wa = [l for l in _rules if m._rule_ident(l)[0] == m.AUDIT_KEY]
t("every watch is perm=wa over the write syscalls of its arch",
  all("-F perm=wa" in l and f"-S {m.AUDIT_WRITE_SYSCALLS[m._rule_ident(l)[1]]} " in l for l in _wa),
  str([l for l in _wa if "-F perm=wa" not in l][:1]))
t("every watched path has a b64 AND a b32 rule (a 32-bit binary writes too)",
  {(i[2], i[3]) for i in map(m._rule_ident, _wa) if i[1] == "b64"}
  == {(i[2], i[3]) for i in map(m._rule_ident, _wa) if i[1] == "b32"})
t("the write list has no read-only or fd-write syscall in it",
  not any(s in m.AUDIT_WRITE_SYSCALLS[a].split(",") for a in ("b64", "b32")
          for s in ("read", "write", "pread64", "pwrite64", "sendto", "recvfrom", "stat", "close")))

print("\n[5a] reading rules back: the file form and the kernel's form are the same rule")
# What `auditctl -l` printed on a real VM (auditd 3.1.2) for rules this file wrote.
_k_watch = ("-a always,exit -F arch=b64 -S open,truncate,ftruncate,rename,mkdir,openat "
            "-F dir=/etc/systemd/system -F perm=wa -F key=woam")
_k_exec = "-a always,exit -F arch=b64 -S execve,execveat -F path=/usr/bin/systemctl -F auid!=-1 -F key=woam-cmd"
_f_exec = f"-a always,exit -F arch=b64 -S execve,execveat -F path=/usr/bin/systemctl -F auid!=unset -k woam-cmd"
t("an exec rule is recognised in force although the kernel rewrote auid and the key",
  m._rule_ident(_k_exec) == m._rule_ident(_f_exec) == ("woam-cmd", "b64", "path", "/usr/bin/systemctl"))
t("a watch is recognised whatever order the kernel prints its syscalls in",
  m._rule_ident(_k_watch) == ("woam", "b64", "dir", "/etc/systemd/system"))
t("path= and dir= on the same path are DIFFERENT rules (a path created as a dir later needs dir=)",
  m._rule_ident(_k_watch.replace("dir=", "path=")) != m._rule_ident(_k_watch))
t("the watched paths come from watches, never from exec rules",
  m._paths_from([_k_watch, _k_exec]) == ["/etc/systemd/system"], str(m._paths_from([_k_watch, _k_exec])))
t("b64 and b32 rules on one path count once",
  m._paths_from([_k_watch, _k_watch.replace("b64", "b32")]) == ["/etc/systemd/system"])
t("an old -w watch from an older woam still counts as watched",
  m._paths_from(["-w /etc/redu-app -p wa -k woam"]) == ["/etc/redu-app"])
t("-c and comments are not rules", m._rule_ident("-c") is None and m._rule_ident("# -a x") is None)

print("\n[5b] a change with no command behind it is the engine's, not the agent's")
# This is the requirement in one assertion: identical container state movement, but only
# the one preceded by a login-session command is the agent's to explain.
_dirty_derived = {"app": {"since": "1970-01-01T00:00:00Z", "subs": [("containers", 1)],
    "files": 1, "named": {"containers": {"modified": ["/x img=y started=z"],
                                         "created": [], "removed": []}}}}
_noaudit = load(None, RULES)          # attribution off entirely
agN, sysN = _noaudit.classify_dirty({k: dict(v) for k, v in _dirty_derived.items()})
t("with attribution OFF a derived change is NOT excused as the engine's",
  "app" in agN and sysN == {}, f"agent={list(agN)} system={list(sysN)}")

_quiet = Path(_tf.mkdtemp()) / "nocmds.log" if False else None
import tempfile as _t2
_q = Path(_t2.mkdtemp()) / "quiet.log"
_q.write_text('type=SYSCALL msg=audit(1785930231.9:1): arch=c000003e syscall=257 '
              'success=yes auid=4294967295 uid=0 ses=4294967295 comm="sh" key="woam"\n')
mQ = load(_q, RULES)
agQ, sysQ = mQ.classify_dirty({k: dict(v) for k, v in _dirty_derived.items()})
t("audit ON and no login-session command ran -> the ENGINE did it, no record demanded",
  "app" in sysQ and agQ == {}, f"agent={list(agQ)} system={list(sysQ)}")

_c = Path(_t2.mkdtemp()) / "cmd.log"
_c.write_text(
    'type=SYSCALL msg=audit(1785930300.1:77): arch=c000003e syscall=59 success=yes '
    'auid=1000 uid=0 ses=99 comm="docker" exe="/usr/bin/docker" key="woam-cmd"\n'
    'type=EXECVE msg=audit(1785930300.1:77): argc=3 a0="docker" a1="restart" a2="keycloak"\n')
mC = load(_c, RULES)
cmds = mC.audit_commands()
t("a login-session command is parsed with its argv",
  len(cmds) == 1 and cmds[0]["argv"] == ["docker", "restart", "keycloak"], str(cmds))
agC, sysC = mC.classify_dirty({k: dict(v) for k, v in _dirty_derived.items()})
t("so the SAME state change becomes the AGENT's to explain",
  "app" in agC and sysC == {}, f"agent={list(agC)} system={list(sysC)}")
t("and the report carries the command that caused it",
  agC["app"].get("commands") == ["docker restart keycloak"], str(agC["app"].get("commands")))

watched = m._paths_from(rules.splitlines())
t("NEVER a watch on / (audit overhead is proportional to breadth)", "/" not in watched, str(watched[:3]))
t("all watches carry the woam key",
  all(f"-k {m.AUDIT_KEY}" in l for l in _rules if m._rule_ident(l)[0] != m.AUDIT_CMD_KEY))
t("covers the group paths", "/etc/redu-app" in watched
  and re.search(r"-F (dir|path)=/etc/redu-app -F perm=wa -k woam\n", rules))
t("no globs survive: auditctl has none", not any("*" in l for l in rules.splitlines()))

# The two that nearly shipped. Both flood the audit log, and the damage is not local:
# auditd rotates at 8MB x 5 by default, so a hot watch silently shortens the attribution
# history for EVERY OTHER group to minutes. A failure that quietly disables the feature
# everywhere is worse than one that breaks loudly in one place.
t("NEVER a recursive watch on /home - agents clone and build there",
  "/home" not in watched, str([w for w in watched if w.startswith("/home")]))
t("a home key file is watched by its real path instead",
  all(w == "/home" or "/.ssh/" in w for w in watched if w.startswith("/home")),
  str([w for w in watched if w.startswith("/home")]))
t("NEVER a recursive watch on the app's own tree - it writes there at runtime",
  "/opt/app" not in watched and "/opt/app-src" not in watched, str(watched))
t("but the app's compose FILES are still watched (config, not runtime)",
  any(w.startswith("/opt/app/") for w in watched), str([w for w in watched if w.startswith("/opt/")]))
t("every watch is an absolute path", all(w.startswith("/") for w in watched))
t("no watch is a bare top-level directory", all(w.count("/") >= 2 for w in watched),
  str([w for w in watched if w.count("/") < 2]))

print("\n[5c] a HELD change must survive, not be absorbed by a fresh baseline")
# `seal --grace` holds a change still inside the window and rebaselines only what it
# accounted for - usually the empty list. `names or list(GROUPS)` treated that empty list
# as "everything", so the held change was absorbed and lost. Measured on a live VM: the
# timer fired 1s after a container restart, printed "holding app (last write 1s ago)", and
# rebaselined the whole machine anyway. The grace window was destroying records, not
# delaying them.
_seen = {"all": 0, "named": []}
_mR = load(FIX / "audit-real.log", RULES)
_mR.hash_group = lambda n: {"hash": "x", "subs": {}}
_mR.save_baseline = lambda b: _seen.__setitem__("saved", dict(b))
_mR.load_baseline = lambda: {}
_mR.rebaseline([])
t("rebaseline([]) touches NO group, not every group",
  _seen.get("saved") == {}, str(_seen.get("saved"))[:80])
_mR.rebaseline(None)
t("rebaseline(None) still means every group",
  set(_seen.get("saved", {})) == set(_mR.GROUPS), str(list(_seen.get("saved", {})))[:80])

print("\n[6] three defects found by an adversarial read of this file")

# (a) THE SERIOUS ONE. `_nfield` returns None for any value it cannot parse as a number,
# including the literal `auid=unset` some builds emit. Folding None into "system" meant an
# unreadable actor was reported as the OS's work - and classify_dirty routes system-only
# groups OUT of the forced write. A parse failure silently excused an agent from recording
# its own change.
import tempfile as _tf
_p = Path(_tf.mkdtemp()) / "unset.log"
_p.write_text(
    'type=SYSCALL msg=audit(1785930231.9:9001): arch=c000003e syscall=257 success=yes '
    'auid=unset uid=0 ses=unset comm="sh" exe="/usr/bin/dash" key="woam"\n'
    'type=PATH msg=audit(1785930231.9:9001): item=1 name="/etc/redu-app/.attrib" '
    'nametype=NORMAL\n')
mU = load(_p, RULES)
evU = mU.audit_writes()
t("an UNPARSEABLE auid is parsed as its own state, not as the OS",
  len(evU) == 1 and evU[0]["actor_kind"] == "unknown", str([e.get("actor_kind") for e in evU]))
t("and is NOT classified as system", len(evU) == 1 and evU[0]["system"] is False)
vU, _a, _h = mU.attribution_for([TARGET])
t("the verdict is 'unattributable', never 'system'", vU == "unattributable", f"got {vU!r}")
agU, sysU = mU.classify_dirty({"app": {"since": "1970-01-01T00:00:00Z", "subs": [("env", 1)],
    "files": 1, "named": {"env": {"modified": [TARGET], "created": [], "removed": []}}}})
t("so it stays INSIDE the gate and is not silently excused",
  "app" in agU and sysU == {}, f"agent={list(agU)} system={list(sysU)}")

# (b) A record can carry several keys when more than one rule watches a path - which is
# what happens the moment woam runs on a CIS/STIG-hardened host, because those baselines
# already watch /etc/passwd, /etc/sudoers and /etc/ssh/sshd_config: woam's `access` group.
_p2 = Path(_tf.mkdtemp()) / "multikey.log"
_p2.write_text(
    'type=SYSCALL msg=audit(1785930231.9:9002): arch=c000003e syscall=257 success=yes '
    'auid=1000 uid=0 ses=42 comm="sed" exe="/usr/bin/sed" key="identity"^"woam"\n'
    'type=PATH msg=audit(1785930231.9:9002): item=1 name="/etc/redu-app/.attrib" '
    'nametype=NORMAL\n')
mM = load(_p2, RULES)
t("a record whose FIRST key belongs to somebody else is still ours",
  len(mM.audit_writes()) == 1, f"got {len(mM.audit_writes())}")
t("and the write is attributed normally", mM.attribution_for([TARGET])[0] == "agent")

# (c) The size guard shrank `why` and never re-measured. A `gap` record has why=None BY
# CONSTRUCTION, so on the very records most likely to be large the guard could not fire.
_big = {"ev": "gap", "group": "app", "id": "abc123", "why": None,
        "what": [f"mod:env:/etc/redu-app/{'x' * 90}-{i}" for i in range(200)],
        "files": 200, "by": "ubuntu(auid=1000,ses=1)"}
import json as _json
_rendered = {}
_orig_open, _orig_write = os.open, os.write
os.open = lambda *a, **k: 0                                    # capture instead of write
os.write = lambda fd, b: _rendered.setdefault("line", b) and None
os.close = lambda fd: None
try:
    m.ROOT = Path(_tf.mkdtemp()); m.LOG = m.ROOT / "changes.jsonl"
    m.append(dict(_big))
finally:
    os.open, os.write = _orig_open, _orig_write
_line = _rendered.get("line", b"")
t("a gap record with why=None is still forced under the atomicity limit",
  0 < len(_line) < 4096, f"{len(_line)} bytes")
t("and it is still one valid JSON line", (lambda: (_json.loads(_line.decode().rstrip('\n')), True)[1])())

print("\n[7] this process's own login identity, free from the kernel")
auid, ses = m.self_login()
t("loginuid is readable without auditd installed", auid is not None, str(auid))
t("sessionid too", ses is not None, str(ses))


print("\n[8] secrets must never enter the record")
# Capturing argv means capturing secrets unless you stop it. Measured the moment USER_CMD
# parsing was switched on, on a real machine:
#   docker exec -e PGPASSWORD=EXAMPLEnotArealPassw0rd1234 redu-dojo-db-1 psql ...
# That was a live database password (an example value here), one step from being copied into changes.jsonl - a
# file whose stated promise is that secrets never enter it. Redact at WRITE: a value that
# never enters the record cannot leak from it later.
_R = m.redact_argv
_cases = [
    (["docker", "exec", "-e", "PGPASSWORD=EXAMPLEnotArealPassw0rd1234", "db"], "EXAMPLEnotArealPassw0rd1234"),
    (["mysql", "-u", "root", "-p", "hunter2"], "hunter2"),
    (["kcadm.sh", "--password", "admin123", "--server", "x"], "admin123"),
    (["curl", "-H", "Authorization:", "Bearer", "eyJhbGciOiJIUzI1NiJ9abc"], "eyJhbGciOiJIUzI1NiJ9abc"),
    (["gh", "auth", "login", "--with-token", "ghp_AbCdEfGh0123456789xyz"], "ghp_AbCdEfGh0123456789xyz"),
    (["app", "--api-key=sk_live_0123456789abcdef"], "sk_live_0123456789abcdef"),
]
for argv, secret in _cases:
    got = " ".join(_R(argv))
    t(f"redacted: {argv[0]} {argv[1] if len(argv) > 1 else ''}".strip(), secret not in got, got[:70])

t("the SHAPE of the command survives redaction",
  " ".join(_R(["docker", "exec", "-e", "PGPASSWORD=x123456", "db", "psql"]))
  == "docker exec -e PGPASSWORD=<redacted> db psql")
t("a command with no secret is untouched",
  _R(["docker", "compose", "up", "-d", "--force-recreate", "keycloak"])
  == ["docker", "compose", "up", "-d", "--force-recreate", "keycloak"])
# The line that made this whole feature worth having must survive.
t("the incident command is still legible",
  " ".join(_R(["sed", "-i", "s/^POSTGRES_PASSWORD=/POSTGRES_PASSWORD=Z/", ".env"]))
  .startswith("sed -i s/^POSTGRES_PASSWORD="))

print(f"\n{_pass} passed, {_fail} failed")
sys.exit(1 if _fail else 0)
