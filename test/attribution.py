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
t("every rule is either a narrow -w watch or an exec rule",
  all(l.startswith("-w ") or l.startswith("-a always,exit ") for l in _rl),
  str([l for l in _rl if not (l.startswith("-w ") or l.startswith("-a always,exit "))][:2]))

# The exec rules are what answer "did an AGENT do this" for state with no file behind it.
# auid!=unset must be in the KERNEL predicate: it is what stops a daemon's own work from
# being recorded at all, which is both the correctness property and the volume control.
_ex = [l for l in _rl if l.startswith("-a always,exit ")]
t("exec rules exist for the state-changing commands", len(_ex) > 0, str(len(_ex)))
t("EVERY exec rule filters auid!=unset in the kernel",
  all("-F auid!=unset" in l for l in _ex),
  str([l for l in _ex if "-F auid!=unset" not in l][:1]))
t("every exec rule is -F perm=x on a resolved absolute path",
  all("-F perm=x" in l and re.search(r"-F path=/", l) for l in _ex))
t("exec rules carry their own key, so they never mix with file writes",
  all(f"-k {m.AUDIT_CMD_KEY}" in l for l in _ex))

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

print("\n[6] three defects found by an adversarial read of this file")
t("NEVER -w / (audit overhead is proportional to breadth)",
  not any(l.startswith("-w / ") or l.strip() == "-w / -p wa -k woam" for l in rules.splitlines()))
t("all watches carry the woam key", all("-k woam" in l for l in rules.splitlines() if l.startswith("-w")))
t("covers the group paths", "-w /etc/redu-app -p wa -k woam" in rules)
t("no globs survive: auditctl has none", not any("*" in l for l in rules.splitlines()))

# The two that nearly shipped. Both flood the audit log, and the damage is not local:
# auditd rotates at 8MB x 5 by default, so a hot watch silently shortens the attribution
# history for EVERY OTHER group to minutes. A failure that quietly disables the feature
# everywhere is worse than one that breaks loudly in one place.
watched = [l.split()[1] for l in rules.splitlines() if l.startswith("-w ")]
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

print(f"\n{_pass} passed, {_fail} failed")
sys.exit(1 if _fail else 0)
