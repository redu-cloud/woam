# woam

**Write-Only Agent Memory.** A record of what changed on a machine and why, so the next
agent (or you, at 2am) does not rediscover it.

One file. Python 3 standard library only. No daemon, no dependencies, no privileges required.
Runs on a cloud VM, a plain Ubuntu box, or a laptop.

```bash
curl -fsSL https://redu.cloud/woam-install.sh | sh
```

```bash
woam                  # state of this machine. Non-zero while a group is unrecorded.
woam show <group>     # what is known about one functional area
woam note <group> "…" # record what you did. The required write. One line.
woam note <group> --defer "…"   # you changed it and cannot explain yet. Still a record.
woam fix <group> "…"  # something in here is WRONG. Correcting it is your job.
woam seal             # the ABANDONED-session case: record WHAT changed, WHY marked missing
woam why <id> "…"     # close a gap later; --unknown if the cause is not established
woam which <path>     # which group does this path belong to
woam groups           # the full path to group map
woam log              # raw append-only records
woam baseline         # take the first snapshot
```

`WOAM_ROOT` overrides `/etc/redu` (used by the test suite, and for running unprivileged).

## The one rule

**If you changed something in a group, record it.** `woam status` exits non-zero until you do,
so `woam && deploy` stops on its own.

Writing costs a few tokens. Not writing costs the next agent thousands rediscovering it, or
worse, sends it down a path that does not work on this machine.

## Why reading is optional and writing is not

**Reading is a private good; writing is a public good.** The agent that reads benefits from
reading. The agent that writes pays the cost and *somebody else* benefits, so writing cannot
depend on goodwill. Reading only has to be useful. Writing has to be required.

That asymmetry is the whole design. Everything below follows from it.

## It records what the AGENT did. Nothing else.

A machine changes constantly on its own: log rotation, unattended upgrades, cron, package
state. **None of that is an agent's doing, and attributing it to one is a lie that costs a
session.**

**The diff engine cannot tell the difference, and never could.** It compares two points in
time and infers, so it has no evidence of who wrote anything. An early version diffed against
a long-lived baseline and told an agent that `/root/.ssh/authorized_keys` and two
`/etc/sudoers.d` files had been **deleted**. Nothing had touched them. A phantom root-key
deletion is exactly the kind of report that burns an hour.

**The kernel already knows.** One audit watch per group path, and every write carries the
identity of whoever caused it:

```
type=SYSCALL ... auid=1000 uid=0 ses=226 comm="sh" exe="/usr/bin/dash" key="woam"
type=PATH    ... name="/etc/redu-app/redu-app.env" nametype=NORMAL
```

- **`auid` is the LOGIN uid and it survives `sudo`.** That process ran as `uid=0`; `auid` is
  still the account that logged in. Nothing in userspace can reconstruct that.
- **`ses` is the PAM session id**: which login did it, exactly.
- **`auid=4294967295` (unset) means no login session was behind the write.** Measured on a
  live VM: an agent's write records `auid=1000`; a `systemd-run` write records the sentinel.

So **`auid != unset` is precisely "an agent or a person did this, not the OS"** - no
heuristic, no time window, no guessing. Measured, both writing to the same file two seconds
apart:

```
  THE SYSTEM DID THESE - no record needed, no login session behind them:

    schedule  cron(1)   (auid unset on every recorded write)

  UNRECORDED CHANGES - these groups changed and nothing says why:

    app       env(1)   since 2026-08-05T11:47:38Z
                BY   ubuntu(auid=1000,ses=226)
                mod  /etc/redu-app/redu-app.env
```

```bash
woam who <path>       # who wrote it, with the session and the program
woam audit-install    # (root) generate the watches from the groups and load them
woam audit-status     # is attribution on, and if not, why not
```

**The verdict is one of five, and four of them are admissions:** `agent`, `system`,
`none` (watched, nothing recorded), `unwatched` (not covered, so nothing can be concluded)
and `no-audit`. Absence of a record only means "the OS did it" for a path we were actually
watching; anywhere else it means we do not know, and woam says so.

With auditd absent, woam still reports **what** changed and states plainly that it cannot
say **who**. It does not fall back to guessing.

### The session-scoped diff is now the fallback, not the mechanism

```
woam session-open <id>      # snapshot at login   (PAM open_session)
woam seal --session <id>    # diff at logout      (PAM close_session)
```

This still works and still bounds the damage on a machine with no auditd: the delta between
those two points is what happened while that agent was logged in. But it is inference, and
its honest limit is that anything the OS does *during* a session is still charged to the
agent. Attribution is what removes that limit; this narrows it.

## The last write is the one nobody does

`woam note` covers the case where an agent explains itself. **`woam seal` covers the case that
actually matters:** the final write, at the moment work finishes, when the agent has no
remaining stake and the session may be ending. It is the highest-value record and the least
likely to happen.

So it does not depend on the agent at all. The WHAT is machine-derived; the WHY is recorded as
explicitly **missing**, with an id anyone can close later:

```
88998d  app: 1 file(s) changed, WHY NOT RECORDED
        mod:env:/etc/redu-app/redu-app.env
        key:env:DISABLE_REGISTRATION changed
```

An honest "nobody said why" beats both silence and a fabricated reason. The next agent learns
the state changed **and** that the reasoning is unknown, so it verifies instead of trusting.
`--unknown` exists so an agent closing a gap never has to invent a cause to satisfy the tool.

History is never rewritten: closing a gap appends a `gap_closed` record carrying both when the
change happened and when it was explained, so the log stays honest about how the knowledge was
acquired.

## Making the last write involuntary

`woam seal` still has to be *called*, which is the same voluntary problem one level up. The
installer removes that with a **systemd timer**: `woam seal --grace 600`, every 10 minutes. An
agent that changes something and walks away still leaves a record naming who did it.

A timer rather than a PAM `close_session` hook, for two reasons. Attribution comes from the
kernel now, so the trigger only has to be automatic, not precise; and **editing
`/etc/pam.d/sshd` can lock a machine out permanently**, with no way back over the network. The
timer also catches what PAM cannot: sessions that never end, and changes made through an API
rather than over ssh. The PAM hooks remain in [`integrations/pam/`](integrations/pam/) for
anyone who wants exact session-end sealing and accepts that risk deliberately.

**Automatic sealing races the agent it is meant to help**, so two things exist to stop it:

- **`--grace 600`.** Without it: an agent edits a file, the timer fires 30 seconds later and
  records "changed, WHY NOT RECORDED", rebaselines, and the agent's own `woam note` then finds
  nothing to attach to. The result is a permanent unexplained gap for a change somebody *did*
  explain. The timestamp comes from the audit record, so it is the real time of the last write,
  and a held group is deliberately **not** rebaselined: otherwise the window would not be
  delaying the record, it would be destroying it.
- **`woam note` closes any gap still open on that group.** The two can cross either way, and a
  log that keeps "nobody said why" next to a note saying exactly why tells every future reader
  the machine is less understood than it is.

Measured on a live VM:

```
a 2s-old write        holding app (last write 2s ago); still inside the 600s grace window
agent explains        recorded against app
                        and closed 3 open gap(s) on app that a seal had left unexplained
agent walks away      ff7bb1  app: 1 file(s) changed, WHY NOT RECORDED
                              by ubuntu(auid=1000,ses=274)
```

`WOAM_TIMER=0` skips installing it.

## The groups

Eight functional areas plus a catch-all, partitioned by what someone is trying to **change**,
not by directory. Every path maps to exactly one, and anything unmatched falls to `host`: a
path mapping to nothing would be a silent hole in the system built to prevent silent holes.

`app` · `service` · `network` · `storage` · `packages` · `access` · `kernel` · `schedule` · `host`

Each group has subgroups with their own file budgets, so one huge tree cannot starve the cheap
config paths that actually matter. A group's digest is the hash of its subgroup digests, so a
change is attributed to a subgroup without rehashing anything else.

## Design notes

- **Volatile facts are stored as a query, never an answer.** `woam show app` prints the command
  to check what is running, not a remembered answer. A remembered answer goes stale, and a
  stale answer is worse than none: without it you check, with it you trust.
- **If you read something wrong here, fixing it is your job.** Nothing in the log is guaranteed
  correct. It is guaranteed honest about where each claim came from. `woam fix` appends a
  correction; history is never rewritten.
- **"Clean" never silently means "I could not look."** Run as a user who cannot read a path and
  it says so explicitly rather than reporting all clear. A fresh install with no baseline
  reports that, rather than reporting no changes.
- **Nothing may ever raise out of woam.** A stack trace is never a useful answer to "what
  changed on this machine", and an agent that sees one concludes the tool is broken and stops
  using it, which loses the memory permanently rather than once. Internal errors exit 1, never
  0: an error is not a clean bill of health.
- Append-only **JSONL**. RFC 8259 forbids a literal newline inside a string, so the record
  delimiter cannot occur inside a record: the one-line rule is enforced by the grammar. Records
  stay under `PIPE_BUF` (4096) so concurrent `O_APPEND` writes are atomic, and a torn write
  costs one record rather than the file.
- Change detection is **metadata only** (path, size, mtime, mode). Content hashing made the
  first version take minutes on a real machine, which means it would simply never be run.
  Current cost on a live VM is about 0.1s.
- Generated trees (`.git`, `node_modules`, `__pycache__`, …) are pruned, and the file count is
  capped per subgroup with the cap **recorded**, so truncation is never silent.
- **Secrets are never stored.** Env files are hashed by key, never read into a record.

## Testing

```bash
bash test/smoke.sh
```

Runs the whole surface against a throwaway `WOAM_ROOT`. No network, no privileges, nothing
installed. It asserts the exit codes that the enforcement depends on, including the two cases
that must never report "clean": a fresh install with no baseline, and an unrecorded change.

## Publishing

`bash publish.sh` copies the tool, its checksum and the installer into the marketing site's
`public/` directory, which is what serves `https://redu.cloud/woam`. It refuses to run if the
smoke test fails.

**This repository is private, so the install URL is the only delivery path.** There is no raw
GitHub fallback and the installer must never grow one: it would ask every machine for a
credential it has no business holding.

## Licence

MIT. See [`LICENSE`](LICENSE).

The distributed files carry an `SPDX-License-Identifier` in their own headers, not only in this
repository. `curl https://redu.cloud/woam` lands a single script on a machine with no `LICENSE`
beside it and no repository to look in, and a recipient who cannot tell what they are permitted
to do with a file has to assume the answer is nothing.
