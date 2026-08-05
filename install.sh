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

# --- first baseline ------------------------------------------------------------
# Without one, the very first `woam` says "NO BASELINE" and exits non-zero, which
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
say "  woam note <group> \"…\"  record what you did"
say "  woam groups           the path to group map"
