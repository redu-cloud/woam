# PAM hooks: session-end sealing (OPT-IN, and not the default)

> **You probably do not need these.** The installer already makes sealing automatic with a
> systemd timer (`woam seal --grace 600`, every 10 minutes), which carries none of the risk
> below. Attribution comes from the kernel, so the trigger only has to be automatic, not
> precise. These hooks buy you exact session-end timing and cost you the possibility of locking
> a machine out permanently. Take them only if you want that trade deliberately.

`woam note` depends on an agent choosing to explain itself. `woam seal` depends on it choosing
to run one more command on its way out. These hooks remove the second dependency: PAM fires
them when the ssh session opens and closes, interactive or not.

## ⚠️ Read this before you touch `/etc/pam.d/sshd`

**Keep a second ssh session open the whole time.** A broken PAM stack locks you out of the box
permanently, and there is no way back in over the network. This is not a theoretical warning.

Both lines below use `optional`, which means PAM ignores the result: a hook that fails, hangs
on a missing binary, or exits non-zero can never block a login. Do not change that to
`required`.

## Install

```sh
install -m 0755 woam-session-start /usr/local/bin/woam-session-start
install -m 0755 woam-session-end   /usr/local/bin/woam-session-end

# append to /etc/pam.d/sshd
session optional pam_exec.so quiet /usr/local/bin/woam-session-start
session optional pam_exec.so quiet /usr/local/bin/woam-session-end

sshd -t          # MUST pass before you trust it
```

Then, from your second session, open a third one and confirm you can still log in.

## What it produces

An agent that connects, changes something and leaves without recording anything gets sealed
anyway:

```
8cc2d8  app: 1 file(s) changed, WHY NOT RECORDED
        key:env:DISABLE_REGISTRATION changed
```

The WHAT is machine-derived. The WHY is recorded as explicitly missing, with an id, so anybody
can close it later with `woam why 8cc2d8 "…"`.

## The honest limits

- **Attribution is by login session, not by process.** Something the OS does *during* a session
  is still attributed to the agent that happened to be logged in. The window is minutes instead
  of days, and it is bounded rather than unbounded, but it is not zero. The mechanism that
  removes this limit entirely is in [`../../docs/DESIGN.md`](../../docs/DESIGN.md).
- **PAM exports no session id.** The hooks key on `$PPID`, which is the sshd process handling
  the connection and is the same in both hooks. If they ever fail to line up, `woam seal` falls
  back to an unscoped diff rather than recording nothing.
- **The log needs rotation.** `/var/log/woam-seal.log` grows with every logout.
