# woam: the design

## The problem

An agent lands on a machine it has never seen. Everything it needs to know about that machine
was learned by a previous agent and then thrown away when that session ended. So it rediscovers
it: reads the same files, runs the same probes, forms the same theory, and sometimes forms a
different and wrong one.

Every document about operating a machine safely was written **for humans**. An agent reads
human procedure and replicates it, hallucination and all. The knowledge that would actually
help is nowhere near the machine where the work happens.

woam is the transport for that knowledge, and it lives on the machine.

## The asymmetry that determines everything

**Reading is a private good. Writing is a public good.**

The agent that reads benefits from reading, immediately and directly. So reading only has to be
*useful*: make it good and it gets used.

The agent that writes pays the cost, and somebody else, later, gets the benefit. Public goods
are systematically under-supplied when they depend on goodwill, and an agent's goodwill lasts
exactly as long as its session. So writing cannot be requested. It has to be **required**.

That is why `woam status` exits non-zero while a group is unrecorded. `woam && deploy` stops on
its own. The enforcement is not a policy document, it is an exit code.

## Why the last write is the one that matters

`woam note` covers the agent that explains itself, which is the easy half.

The write that carries the most information is the **last** one: at the moment work finishes,
when the state has actually changed and the reason is still known. It is also the least likely
to happen, because at that moment the agent has no remaining stake and the session may already
be ending.

So `woam seal` does not depend on the agent at all. The WHAT is machine-derived. The WHY is
recorded as explicitly **missing**, with an id that anybody can close later.

An honest "nobody said why" beats both silence and a fabricated reason. Silence teaches the next
agent nothing. A fabricated reason teaches it something false, which is worse than nothing,
because without a reason it checks and with one it trusts.

## Attribution: snapshot/diff was the wrong foundation

The first version compared two filesystem snapshots and inferred who was responsible. It has no
evidence of who wrote anything. It compares two points in time, so it is **structurally
incapable of attribution**, and every attribution bug it produced traces back to that one
choice: an early build reported that `/root/.ssh/authorized_keys` and two `/etc/sudoers.d` files
had been deleted, when nothing had touched them.

Scoping the diff to a login session bounds the damage (see the PAM integration) but does not fix
the foundation. Anything the OS does *during* the session is still attributed to the agent.

**The kernel already records the evidence.** One `auditd` watch:

```sh
auditctl -w /etc/redu-app -p wa -k reduapp
```

produces, for a real write:

```
auid=1000  uid=0  ses=181  comm="sed"  exe="/usr/bin/sed"  success=yes  AUID="ubuntu"
```

- **`auid` is the login uid and it survives sudo.** The process above ran as `uid=0`; `auid` is
  still the human or agent who logged in. No snapshot can recover that.
- **`ses` is the PAM session id**, which answers "which login did this" directly.
- `comm` and `exe` name the program, and `success` says whether the write actually landed.

And it separates agents from the system cleanly. Measured on one machine:

| write | record |
|---|---|
| agent, over its ssh session | `auid=1000  ses=187` |
| system, via a systemd unit | `auid=4294967295  ses=4294967295` (unset) |

`4294967295` is the sentinel for "no login session behind this". So **`auid != unset` is exactly
'an agent or a human did this'**: no heuristic, no time window, no misattribution.

The intended shape, therefore, is two layers: **auditd is the attribution layer** (who, which
session, which program) and **the diff is the content layer** (what the file now says). Diff
alone was never going to be enough.

Costs, stated rather than hidden: `auditd` is a package and is not installed by default on a
stock cloud image; watches add kernel overhead proportional to how broadly they are set, so they
go on the group paths and never on `/`; and the audit log needs rotation.

## What is deliberately not stored

**Volatile facts are stored as a query, never an answer.** `woam show app` prints the command to
check what is running. It does not print a remembered answer, because a remembered answer goes
stale silently, and a stale answer is worse than none: without it you check, with it you trust.

**Secrets are never stored.** Env files are compared by key digest. No value ever enters a
record.

**Nothing is guaranteed correct, and that is stated.** The log is guaranteed honest about where
each claim came from. If an agent reads something wrong, correcting it is that agent's job:
`woam fix` appends a correction and history is never rewritten.

## Failure behaviour

A tool in the audit path has one failure mode that must not exist: reporting "clean" when it
does not know.

- A fresh install with no baseline says so, and exits non-zero. It does not say "no changes".
- A path it cannot read is reported as **not visible**, by name, rather than counted as empty.
- A file that was seen before and is unreadable now is reported as unreadable, not as deleted.
- Truncation is recorded. Each subgroup has a file budget, and hitting it appears in the record.
- An internal error prints the error, states plainly that this is not a clean bill of health,
  and exits 1.
- Nothing may raise out of the program. A stack trace is never a useful answer to "what changed
  on this machine", and an agent that sees one concludes the tool is broken and stops using it,
  which loses the memory permanently rather than once.

## Cost

Change detection is **metadata only**: path, size, mtime, mode. The first version hashed file
contents and took minutes on a real machine, which means in practice it would never have been
run. A tool that is required to run before every deploy has to cost about as much as `ls`.
Current cost on a live VM is roughly 0.1s.

Generated trees (`.git`, `node_modules`, `__pycache__`, and similar) are pruned. Groups are
split into subgroups with independent budgets so that one large tree cannot starve the small
config paths that carry the most meaning per byte. A group's digest is the hash of its subgroup
digests, so a change is localised to a subgroup without rehashing anything else.

## Storage format

Append-only JSONL, one record per line.

RFC 8259 forbids a literal newline inside a string, so the record delimiter cannot occur inside
a record: the one-line rule is enforced by the grammar rather than by convention. Records are
kept under `PIPE_BUF` (4096 bytes) so that concurrent `O_APPEND` writes are atomic, and a torn
write costs one record instead of the file.

No daemon. Nothing to die, no privileges required, and identical behaviour on a laptop and on a
server.
