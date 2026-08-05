#!/bin/sh
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 redu.cloud
# woam installer.
#
#   curl -fsSL https://redu.cloud/woam-install.sh | sh
#
# POSIX sh, no bashisms: this runs on whatever /bin/sh the image happens to ship.
#
# It VERIFIES the download before installing it. Not for security (the checksum
# comes from the same origin as the file, so it defends against nothing an
# attacker who controls that origin could not also change) but against the
# failure that actually happens: a truncated download. Half a Python file
# installed into /usr/local/bin is a tool that reports nothing and looks fine,
# which is the exact failure woam exists to prevent.
set -eu

BASE="${WOAM_URL_BASE:-https://redu.cloud}"
PREFIX="${WOAM_PREFIX:-/usr/local/bin}"
DEST="$PREFIX/woam"

say() { printf '%s\n' "$*"; }
die() { printf 'woam-install: %s\n' "$*" >&2; exit 1; }

# --- prerequisites, named individually so a failure says which one ------------
command -v python3 >/dev/null 2>&1 || die "python3 not found. woam is a Python 3 script."

if command -v curl >/dev/null 2>&1; then
  fetch() { curl -fsSL "$1" -o "$2"; }
elif command -v wget >/dev/null 2>&1; then
  fetch() { wget -qO "$2" "$1"; }
else
  die "neither curl nor wget found."
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT INT TERM

say "woam: fetching $BASE/woam"
fetch "$BASE/woam" "$TMP/woam" || die "download failed: $BASE/woam"

# --- verify -------------------------------------------------------------------
SUM=""
if [ -n "${WOAM_SHA256:-}" ]; then
  SUM="$WOAM_SHA256"
elif fetch "$BASE/woam.sha256" "$TMP/woam.sha256" 2>/dev/null; then
  SUM="$(cut -d' ' -f1 <"$TMP/woam.sha256")"
fi

if [ -n "$SUM" ]; then
  if command -v sha256sum >/dev/null 2>&1; then
    GOT="$(sha256sum <"$TMP/woam" | cut -d' ' -f1)"
  elif command -v shasum >/dev/null 2>&1; then
    GOT="$(shasum -a 256 <"$TMP/woam" | cut -d' ' -f1)"
  else
    GOT=""
  fi
  if [ -z "$GOT" ]; then
    say "woam: no sha256 tool available, skipping verification"
  elif [ "$GOT" != "$SUM" ]; then
    die "checksum mismatch (expected $SUM, got $GOT). NOT installed."
  fi
else
  # Say it out loud. A silent skip is how an unverified install passes for a
  # verified one.
  say "woam: no checksum published, installing unverified"
fi

# --- prove it runs BEFORE it becomes the installed tool ------------------------
python3 "$TMP/woam" --help >/dev/null 2>&1 || die "the downloaded file does not run. NOT installed."

# --- install ------------------------------------------------------------------
chmod 0755 "$TMP/woam"
if [ -w "$PREFIX" ]; then
  mv "$TMP/woam" "$DEST"
elif command -v sudo >/dev/null 2>&1; then
  sudo mv "$TMP/woam" "$DEST" && sudo chmod 0755 "$DEST"
else
  die "$PREFIX is not writable and sudo is not available. Set WOAM_PREFIX to a writable directory."
fi
say "woam: installed $DEST"

# --- attribution ---------------------------------------------------------------
# Without this woam can tell you WHAT changed but not WHO changed it, and it will say so
# rather than guess. auditd is the only thing on the machine that knows: auid is the login
# uid, it survives sudo, and auid=4294967295 means no login session was behind a write. So
# `auid != unset` is exactly "an agent or a person did this, not the OS".
#
# Everything here is best-effort and bounded. A machine with change detection and no
# attribution is useful; a machine whose provisioning hung on apt is not.
if [ "${WOAM_AUDIT:-1}" = "1" ] && [ "$(id -u)" = "0" ]; then
  if ! command -v auditctl >/dev/null 2>&1; then
    say "woam: installing auditd (attribution layer)"
    # Lock::Timeout rather than a hand-rolled wait loop: cloud-init and
    # unattended-upgrades hold the apt lock at exactly this point in a boot.
    DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=180 install -y auditd \
      >>/var/log/woam-install.log 2>&1 || say "woam: auditd install failed, continuing without attribution"
  fi
  if command -v auditctl >/dev/null 2>&1; then
    systemctl enable --now auditd >/dev/null 2>&1 || true
    "$DEST" audit-install >/dev/null 2>&1 && say "woam: attribution ON (auditd watches installed)" \
      || say "woam: auditd present but watches did not load; woam will report attribution as UNKNOWN"
  fi
elif [ "${WOAM_AUDIT:-1}" = "1" ]; then
  say "woam: not root, skipping attribution setup.  sudo woam audit-install  turns it on."
fi

# --- make the last write involuntary --------------------------------------------
# `woam seal` is the record that matters most and the one nobody makes: it happens
# when the work is finished, the agent has no remaining stake, and the session may
# already be ending. Depending on an agent to run it is the same voluntary problem
# one level up from `woam note`.
#
# A systemd timer, NOT a PAM hook. The PAM route fires exactly at session end, which
# mattered when session boundaries were how we inferred who did what. Attribution now
# comes from the kernel, so the trigger only has to be automatic, not precise. And
# editing /etc/pam.d/sshd can lock a machine out permanently, with no way back in over
# the network. That is not a risk worth taking on a customer's VM for a timing
# refinement we no longer need.
#
# The timer is also strictly better here: it catches long-lived sessions that never
# end, and changes made through the API rather than over ssh. The PAM hooks are still
# in integrations/pam/ for anyone who wants exact session-end sealing and accepts the
# lockout risk deliberately.
if [ "${WOAM_TIMER:-1}" = "1" ] && [ "$(id -u)" = "0" ] && command -v systemctl >/dev/null 2>&1; then
  cat >/etc/systemd/system/woam-seal.service <<'UNIT'
[Unit]
Description=woam: record what changed on this machine, and who changed it
After=auditd.service
Wants=auditd.service

[Service]
Type=oneshot
# Refresh the watches first. auditctl refuses a watch on a path that does not
# exist yet, so a path the app creates after provisioning is never watched unless
# something retries. Idempotent: rules already in force are skipped.
ExecStartPre=-/usr/local/bin/woam audit-install
ExecStart=/usr/local/bin/woam seal --grace 600
Nice=10
IOSchedulingClass=idle
TimeoutStartSec=120
User=root
UNIT
  cat >/etc/systemd/system/woam-seal.timer <<'UNIT'
[Unit]
Description=woam: seal unexplained changes periodically

[Timer]
OnBootSec=10min
OnUnitActiveSec=10min
RandomizedDelaySec=120
Persistent=true

[Install]
WantedBy=timers.target
UNIT
  systemctl daemon-reload >/dev/null 2>&1 || true
  if systemctl enable --now woam-seal.timer >/dev/null 2>&1; then
    say "woam: sealing is automatic (systemd timer, every 10min, 10min grace)"
  else
    # Say it. A silent failure here means the last write quietly goes back to being
    # voluntary, which is the failure this whole mechanism exists to remove.
    say "woam: could not enable the seal timer; sealing is MANUAL on this machine"
  fi
fi

# --- first baseline, LAST ------------------------------------------------------
# The order matters and getting it wrong is not cosmetic. Measured on a real first
# boot: with the baseline taken BEFORE the auditd install, installing auditd itself
# then showed up as an unrecorded change, and the very first `woam` an agent ran on
# a brand-new VM exited 1 blaming it for woam's own installation:
#
#     service   vendor(2)     cre /lib/systemd/system/auditd.service
#     packages  installed(1)  mod /var/lib/dpkg/status
#
# That is precisely the failure the "woam runs last in runcmd" rule exists to
# prevent, reproduced one level down inside the installer. An agent whose first
# encounter with the tool is a false accusation learns to ignore it, and the whole
# thing is worth nothing after that.
#
# So: baseline once, at the very end, when the machine is actually in its finished
# state. Without one, the first `woam` says "NO BASELINE" and exits non-zero, which
# is correct but is a poor first impression of a tool whose job is to be run.
ROOT="${WOAM_ROOT:-/etc/redu}"
if mkdir -p "$ROOT" 2>/dev/null && [ -w "$ROOT" ]; then
  "$DEST" baseline >/dev/null 2>&1 && say "woam: baseline recorded in $ROOT"
elif command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
  sudo "$DEST" baseline >/dev/null 2>&1 && say "woam: baseline recorded in $ROOT"
else
  say "woam: take the first snapshot with:  sudo woam baseline"
fi

say ""
say "  woam                  what changed on this machine, and why"
say "  woam who <path>       who wrote it: auid survives sudo, so this is evidence"
say "  woam note <group> \"…\"  record what you did"
say "  woam groups           the path to group map"
