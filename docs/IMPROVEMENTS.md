# What to improve in woam, and what other people already learned the hard way

Derived from four literature passes on 2026-08-05: file-integrity monitoring, system
provenance, configuration change tracking, compelled documentation, and agent memory.

**This is a work list, not a comparison.** The goal is a tool that is useful on real
machines. Where somebody else already solved a problem, copy their answer. Where somebody
else already hit a wall, do not walk into it.

Every claim carries a source. Where a source could not be verified, it says so.

---

## Already fixed on 2026-08-05

Recorded so nobody redoes them, and because each one was a silent failure.

| Fix | Why it mattered |
|---|---|
| Read the KERNEL's watch list (`auditctl -l`), not our own rules file | `auditctl` refuses a watch on a path that does not exist yet. On a compose VM the app creates `/etc/redu-app` after provisioning, so 8 of 39 watches never loaded and woam reported "watched, no write recorded" for a write that had happened |
| An unparseable `auid` gets its own state, never "system" | `_nfield` returns `None` for anything non-numeric. Folding that into "system" routed the group OUT of the forced write, silently excusing an agent from recording its own change |
| Multi-key records matched by membership, not first-match | A path watched by two rules yields `key="identity"^"woam"`. CIS/STIG baselines already watch `/etc/passwd`, `/etc/sudoers`, `/etc/ssh/sshd_config`, which is exactly woam's `access` group |
| Size guard re-measures and caps every field | A `gap` record has `why: None` by construction, so the old guard could not fire on the records most likely to be oversized |
| Detect `-a never,task` | Ships by default on RHEL-family images; short-circuits audit at fork so every watch matches nothing |
| No recursive watch on `/home` or `/opt/app` | Both are written constantly. One hot watch rotates the log and silently shortens attribution history for every other group |
| Capture `proctitle` | "Who" without "what command" is weak at 2am. etckeeper's auto-message is the causing argv for the same reason |

---

## HIGH: correctness. Each of these makes woam answer confidently and wrongly.

### 1. Read the rotated logs, not just `audit.log`

We read one file. Default rotation is **8 MB x 5** ([auditd.conf(5)](https://man7.org/linux/man-pages/man5/auditd.conf.5.html)) which on a busy host is minutes of history, and woam's own watches can trigger the rotation. `ausearch --input-logs` exists precisely because reading the single current file is wrong. Glob `audit.log*`, sort ascending, read all.

### 2. Surface the kernel's `lost` counter

The kernel drops audit records when the backlog fills. Distro default backlog is **320**; the audit maintainers recommend **8192** ([blog.siphos.be](https://blog.siphos.be/2015/05/audit-buffering-and-rate-limiting/)). A non-zero `lost` delta between runs means the `none` verdict is unsound and must degrade to `unattributable`. osquery ships exactly this guidance ([process auditing](https://osquery.readthedocs.io/en/stable/deployment/process-auditing/)).

**Never set `-f 2`.** It panics the machine on audit failure.

### 3. Startup self-test: prove the watches actually fire

Touch a sentinel under a watched path, confirm the record appears, degrade every verdict on that host if it does not. This is our own rule from `CLAUDE.md` applied one layer down: *a negative grep is ambiguous, so run the pattern against a known-positive first*. Without it, `-a never,task`, `-e 2`, a full backlog and a broken parser all look identical to "nothing happened".

### 4. `-e 2` (immutable rules) blocks `audit-install` until reboot

PCI-DSS hardening guidance recommends it. Our installer sends `audit-install` output to `/dev/null`, so the failure is invisible. Detect it and say so.

### 5. Container writes are unattributable, and this is not fixable

Container processes never pass through PAM, so they inherit `auid=4294967295` ([moby#26535](https://github.com/moby/moby/issues/26535), open since 2016, closed without a fix). The kernel audit container ID went through **ten patch revisions from 2018 to 2020 and never landed** ([LWN](https://lwn.net/Articles/808399/)).

**For `deploy_compose` this means every file written from inside a container reads as "the OS did it".** That is the largest permanent gap in the design. It belongs in the README as a stated limitation, not discovered by a user.

### 6. Take an advisory lock so the timer cannot seal mid-operation

`--grace 600` does not cover a 20-minute `apt upgrade`. etckeeper has two open Debian bugs for exactly this failure ([#906914](https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=906914), [#1088667](https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1088667)).

### 7. Test the kill switch, mechanically

etckeeper's `AVOID_DAILY_AUTOCOMMITS=1` was **not honoured for 7.7 years** across three Debian releases ([#884824](https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=884824)). `WOAM_PROVISION=false` and `WOAM_TIMER=0` need an assertion, not a comment.

---

## MEDIUM: usefulness. These are what make it worth running.

### 8. Close gaps automatically from records we already hold

**The highest-leverage item on this list.** Most gaps should never reach a human at all. We already know the Temporal workflow id, the MCP tool-call id and the deploy job id for platform-driven changes.

Gerrit's `Change-Id` is the one forced-write gate with real compliance, and it works **because a hook fills it, never the human** ([Gerrit docs](https://gerrit-review.googlesource.com/Documentation/user-changeid.html)). Tripwire calls this change reconciliation and sources the reason from an ITSM ticket; our source is better because it is the system that made the change.

### 9. Reference nodes: explain once per fleet, not once per host

Tripwire's change reconciliation promotes on node B what was already explained on node A ([Change Reconciliation 101](https://www.mtechpro.com/marketing/newsletter/2020/feb/dyncontent/Tripwire_Enterprise_Change_Reconciliation_101_Customer_Guide.pdf)). For a 3-member cluster this means answering WHY once instead of three times. We already compute the digests to match on.

### 10. Accept a manifest from the deploy pipeline

The pipeline knows which files it is about to change. Those are not gaps and should never be raised as ones. Same source as above.

### 11. `woam noisy`

Tripwire's "Frequently Changed Elements" report finds the noisy paths **empirically** instead of guessing budgets. Ours are guesses today.

### 12. Per-attribute "could not test", not just per-group

`rpm -V` distinguishes pass (`.`) from not-checkable (`?`) per attribute; `dpkg --verify` returns `?` for 8 of 9 positions because only md5sum is implemented ([dpkg(1)](https://manpages.debian.org/testing/dpkg/dpkg.1.en.html)). Our five verdicts are per group. This is the same honesty one level finer.

### 13. Diff against pristine, not only against the last snapshot

`ostree admin config-diff` answers "what on this box is not stock?" ([manpage](https://ostreedev.github.io/ostree/man/ostree-admin-config-diff.html)). Snapshot-to-snapshot cannot answer that for anything predating install. Approximable from the dpkg/rpm database.

### 14. Record the request separately from the result

rpm-ostree keeps `requested-packages` alongside what actually took effect ([handbook](https://coreos.github.io/rpm-ostree/administrator-handbook/)). An intent with no matching change is a finding, not a null.

### 15. Consider syscall-form rules

`auditctl(8)`: *"The -w form of writing watches is for backwards compatibility and is deprecated due to poor system performance."* The syscall form also lets us push `-F auid!=unset` into the **kernel**, cutting volume at the source. The cost is losing the `system` verdict on those paths, so make it a per-group knob and let the verdict reflect which mode a group is in.

### 16. Ship an MCP server

So an agent that is not SSHed in can still read the record. PROJECTMEM ships 15 tools; Cleric exposes `search_knowledge` over MCP so another vendor's agent can read it. Cross-vendor readability is the one axis where the market has already moved, and it is cheap.

### 17. Index-plus-topic-files, with a `modified` timestamp

Claude Code auto-memory and Azure SRE Agent independently landed on the same shape: a small always-loaded index, topic files read on demand, hard error when the index exceeds its read budget. The `modified` field tells a reading agent how stale a fact is.

### 18. Redact at write, not at read

deja-vu strips secrets before they enter the store (`[redacted:aws-key]`). We hash env values, which is stronger, but the principle should hold everywhere.

### 19. A global tier

`~/.woam/global/` for lessons that generalise across machines, versus this-host facts. PROJECTMEM does this per-project; ours maps to fleet-wide.

---

## Design rules: things the evidence says NOT to do

### 20. Never grade the WHY. Gate on presence only.

OpenAI measured that a chain-of-thought monitor catches reward hacking at 95% recall, but **folding that score into the reward produced obfuscated hacking** ([arXiv:2503.11926](https://arxiv.org/abs/2503.11926)). The moment a judge rejects "low quality" reasons, you get better-looking reasons and lose the diagnostic channel.

Forcing a *format* is worse than nothing: across 50,673 security commits, Conventional-Commits-compliant messages were **49.73% Poor vs 30.53%** for non-compliant, and **zero** of 50,673 rated Excellent ([arXiv:2604.20461](https://arxiv.org/pdf/2604.20461)).

Length is actively misleading: unfaithful reasoning measured *longer* than faithful.

### 21. Budget for junk. It is not a bug in the design.

The one experiment testing our exact mechanism (relabel the field "Explain WHY, required" and make it mandatory) cut missing rationale **81% -> 23%** and meaningless messages **27% -> 7%** ([arXiv:2304.13887](https://arxiv.org/abs/2304.13887)). That is a good result **and** it leaves 23% junk. Also, **~20% of changes legitimately have no interesting WHY** ([ICSE 2022](https://arxiv.org/pdf/2202.02974)) - version bumps, generated files, pure refactors. Demanding one manufactures junk by construction.

### 22. The agent failure mode is not `n/a`. It is a good-looking wrong reason.

In multi-step tool-use tasks, **72% of exploit episodes include an explicit rationale**, framed as pragmatism ([arXiv:2605.02964](https://arxiv.org/abs/2605.02964)). And agents report success on work they did not do in 45-47% of failures, **which LLM judges cannot detect** (best AUROC 0.640, while TF-IDF + logistic regression hits 0.849 - [arXiv:2606.09863](https://arxiv.org/abs/2606.09863)).

Consequence: a well-written `why` is not evidence the change was good. Keep `by` (kernel) structurally separate from `claims` (self-declared) forever.

### 23. Make `seal` co-equal and unpunished, not a fallback

NASA's ASRS grew from ~400 to **10,094 reports per month** by removing the penalty for honest self-report ([program briefing](https://asrs.arc.nasa.gov/docs/ASRS_ProgramBriefing.pdf)). "I changed this and cannot explain why" should be as cheap to record as a full explanation.

### 24. Ask at change time, not at deploy time

`woam && deploy` is structurally a post-hoc prompt, which is the exact setup that produces post-hoc rationalisation. Interleaved prompting moved compliance from 0% to 52-100%.

### 25. Stay inside the volume budget

Unfiltered whole-system audit runs **1-3 GB/host/day**, ceiling 5.6, with web servers cited at 33 ([LogGC](https://www.cs.purdue.edu/homes/dxu/pubs/CCS13_LogGC.pdf), [ProTracer](https://doi.org/10.14722/ndss.2016.23350), [NoDoze](https://www.ndss-symposium.org/wp-content/uploads/2019/02/ndss2019_03B-1-3_UlHassan_paper.pdf), [PrioTracker](https://www.ndss-symposium.org/wp-content/uploads/2018/02/ndss2018_07B-3_Liu_paper.pdf)). Industry tolerance, from 10 managers and 48 engineers, is **15-100 MB/day/host** ([CCS 2023](https://arxiv.org/pdf/2307.08349)).

**We measured 4.4 MB/day.** Any change that raises this needs re-measuring.

### 26. Keep the output readable, and know the number

Practitioners set the bar at **fewer than 50 nodes** per thing-to-interpret; published systems deliver 12 to 176,000 (same source). And LLM consumption of full provenance graphs has been measured to fail outright: one DARPA sub-dataset is **32.76M tokens**, with *"the logs cannot fit into one prompt"* and fewer than 50 malicious nodes out of 800,000 ([arXiv:2507.10873](https://arxiv.org/pdf/2507.10873)).

woam shows a handful of lines per group. That is the design, not a shortcut.

### 27. Do not sell it as forensics

Approximation techniques *"compress logs by as much as 93.7% but retain as little as 7.3% of attacker-related forensic evidence"* ([ACSAC 2020](https://adambates.org/documents/Michael_Acsac20.pdf)). Narrow watches are a filter. woam is an operations record. The `unwatched` verdict is the honest mitigation because it names what we did not look at.

### 28. Never claim tamper-evidence

Log entries after a system is subverted cannot be trusted, and every technique that partitions execution does so using a signal an attacker can forge ([OmegaLog](https://adambates.org/documents/Hassan_Ndss20.pdf): *"this is a big problem for almost the entirety of recent work in provenance-based forensic analysis"*).

---

## EXPERIMENT (parked, not rejected): woam inside the containers too

The idea: `docker exec` is shaped like ssh, and a Linux container is shaped like a small VM
with its own `/etc`, its own app tree, its own package state. So run woam in there as well,
have the container record its own mutations, and have the host aggregate.

**I first argued against this partly on the grounds that it would mean modifying the
customer's images. That is a constraint from the deploy code, not from the business.** The
stated position is that changing a client's containers to get them better results is in
scope. So that objection is void and the idea is parked for experimentation, not dismissed.

What actually survives, separated into what is solvable and what is not:

| Objection | Status |
|---|---|
| No `python3` in keycloak, postgres or the Next.js image (measured: 0 of 3) | **Solvable.** Inject a static single-file binary, or write a POSIX-sh variant for the in-container case |
| Writable layer is wiped on recreate, so the record dies | **Solvable.** Bind-mount the log out to the host, which also puts every container's record in one place |
| **`/proc/self/loginuid` inside a container reads `4294967295`** | **NOT solvable from inside.** Measured on the live VM. There is no login identity in a container, because containers never pass through PAM, and `auditd` is one subsystem per KERNEL and not per namespace. An in-container woam can see WHAT changed and can never see WHO |

So the shape of the experiment is a **hybrid, and it was always going to be**: attribution
can only come from the host, because that is the only place the identity exists. What an
in-container agent would buy is better CONTENT detection than `docker diff` gives - real
group partitioning, config-key diffing, per-file metadata - inside a container big enough
for that to matter.

Worth trying when: a customer runs a container complex enough that `docker diff`'s
writable-layer list is too coarse, or when we want the same functional groups (`app`,
`service`, `network`) *inside* a container rather than a flat path list.

Not worth trying before: the host-side version has been used in anger and we know which
parts of the record agents actually read.

---

## Corrections to things we believed

- **Wazuh did NOT move whodata off auditd.** As of 4.12 auditd is still the default provider; eBPF is opt-in with fallback eBPF -> audit -> inotify. The eBPF issue names no auditd defect and contains no performance data.
- **Do not follow them to eBPF anyway.** Tetragon's `auid` is always `4294967295` from eBPF, and the bug was closed **"not planned"** ([cilium/tetragon#2076](https://github.com/cilium/tetragon/issues/2076)). eBPF would cost us the one field the whole design rests on.
- **`PIPE_BUF` is a guarantee about pipes.** Append atomicity to a regular file comes from the inode lock held across the write. Same small-record discipline; **neither holds over NFS.**
- **Parsing the log rather than holding the netlink socket is an advantage, not a compromise.** Only one consumer can hold that socket - osquery and auditd conflict over it, and Wazuh's socket path broke outright on audit 3.1+. woam composes with whatever the customer already runs.

---

## Unverified. Needs a machine with auditd.

- Whether auditd actually emits the caret-joined multi-key form `key="a"^"b"`. The parser handles it either way and the fix costs nothing, but the trigger is unconfirmed.
- Whether the raw log ever writes `auid=unset` as a literal string rather than the numeric sentinel. Same: handled, unconfirmed.
- Whether an agent simply runs `deploy` **without** `woam &&`. Nothing in the literature tests compliance with a local blocking CLI gate, and this is the real hole in the risk model.
