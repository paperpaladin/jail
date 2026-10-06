#!/bin/sh
# The oracle. Every assertion below is a real syscall made by a real process
# running under `jail`, and the thing asserted is the kernel's own verdict:
# exit 0 means the syscall succeeded, exit 13 means the kernel returned EACCES.
# Nothing here inspects jail's internal state, parses its output, or trusts it
# about anything. The kernel is the authority.
set -u

ROOT=$(cd "$(dirname "$0")/.." && pwd)
J="$ROOT/jail"
TRY="$ROOT/t/try"

pass=0; fail=0; skip=0

ok()   { pass=$((pass + 1)); printf 'ok    %s\n' "$1"; }
bad()  { fail=$((fail + 1)); printf 'FAIL  %s\n' "$1"
         shift; printf '%s\n' "$@" | sed 's/^/      | /'; }
skipt(){ skip=$((skip + 1)); printf 'skip  %s  (%s)\n' "$1" "$2"; }

# t NAME WANT_STATUS -- CMD...   assert the exit status of CMD
t() {
	_n=$1; _w=$2; shift 3
	_o=$("$@" 2>&1); _s=$?
	if [ "$_s" -eq "$_w" ]; then ok "$_n"
	else bad "$_n" "want status $_w, got $_s" "$_o"; fi
}

# tout NAME WANT_STATUS WANT_STDOUT -- CMD...   assert status AND exact stdout
tout() {
	_n=$1; _w=$2; _e=$3; shift 4
	_o=$("$@" 2>/dev/null); _s=$?
	if [ "$_s" -eq "$_w" ] && [ "$_o" = "$_e" ]; then ok "$_n"
	else bad "$_n" "want status $_w stdout [$_e], got status $_s stdout [$_o]"; fi
}

[ -x "$J" ] && [ -x "$TRY" ] || { echo "run 'make' first" >&2; exit 2; }

# --- is Landlock actually here? skip loudly, never silently pass -------------
abi=$("$J" --abi 2>/dev/null)
if [ -z "$abi" ] || [ "$abi" = 0 ]; then
	echo "Landlock is not available on this kernel ($(uname -r))."
	echo "Either CONFIG_SECURITY_LANDLOCK=n, or landlock is missing from the"
	echo "kernel's lsm= list. Every filesystem-confinement test needs the"
	echo "kernel to be the oracle, so they are SKIPPED, not passed."
	for n in read-allowed read-denied write-ro write-rw create unlink mkdir \
	         list truncate inherit-grandchild cannot-unsandbox \
	         transparency-status transparency-stdout; do
		skipt "$n" "no landlock"
	done
	printf '\n%d passed, %d failed, %d skipped\n' "$pass" "$fail" "$skip"
	exit 0
fi
echo "landlock ABI $abi on $(uname -r)"
echo

# --- fixture ----------------------------------------------------------------
TD=$(mktemp -d) || exit 2
trap 'chmod -R u+rwX "$TD" 2>/dev/null; rm -rf "$TD"' EXIT INT TERM
mkdir -p "$TD/ro" "$TD/rw" "$TD/deny"
echo readable      > "$TD/ro/file"
echo writable      > "$TD/rw/file"
echo "top secret"  > "$TD/deny/secret"

# The sandbox under test: read+exec on the probe binary, read on ro/, write on
# rw/. Note what is NOT granted: /etc, /dev, /proc, $TD itself, $TD/deny, and
# the repo root. /tmp is not granted either -- only the two subdirectories.
SB="--ro $ROOT/t --ro $TD/ro --rw $TD/rw"
# For tests that need a real shell, which needs the loader and libc.
SBSH="$SB --ro /usr"

# ===========================================================================
# 1. reading an allowed path succeeds
# ===========================================================================
t 'read allowed file'          0  -- "$J" $SB -- "$TRY" read  "$TD/ro/file"
t 'read allowed file in rw'    0  -- "$J" $SB -- "$TRY" read  "$TD/rw/file"
t 'list allowed directory'     0  -- "$J" $SB -- "$TRY" list  "$TD/ro"

# ===========================================================================
# 2. reading a path NOT in the allowlist fails with EACCES
# ===========================================================================
t 'read unlisted file'        13  -- "$J" $SB -- "$TRY" read  "$TD/deny/secret"
t 'read /etc/passwd'          13  -- "$J" $SB -- "$TRY" read  /etc/passwd
t 'list unlisted directory'   13  -- "$J" $SB -- "$TRY" list  "$TD/deny"
t 'list /'                    13  -- "$J" $SB -- "$TRY" list  /
# Not granted even though it is the *parent* of two granted paths: Landlock
# grants beneath a path, never above it.
t 'list parent of granted'    13  -- "$J" $SB -- "$TRY" list  "$TD"

printf '\n%d passed, %d failed, %d skipped\n' "$pass" "$fail" "$skip"
[ "$fail" -eq 0 ]
