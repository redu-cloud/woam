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
t("every rule is a narrow -w watch", all(l.startswith("-w ") for l in rules.splitlines() if not l.startswith("#")))
t("NEVER -w / (audit overhead is proportional to breadth)",
  not any(l.startswith("-w / ") or l.strip() == "-w / -p wa -k woam" for l in rules.splitlines()))
t("all watches carry the woam key", all("-k woam" in l for l in rules.splitlines() if l.startswith("-w")))
t("covers the group paths", "-w /etc/redu-app -p wa -k woam" in rules)
t("glob roots are reduced to a literal stem auditctl accepts",
  not any("*" in l for l in rules.splitlines()))

print("\n[6] this process's own login identity, free from the kernel")
auid, ses = m.self_login()
t("loginuid is readable without auditd installed", auid is not None, str(auid))
t("sessionid too", ses is not None, str(ses))

print(f"\n{_pass} passed, {_fail} failed")
sys.exit(1 if _fail else 0)
