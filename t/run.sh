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

# ===========================================================================
# 3. writing to a read-only path fails
# ===========================================================================
t 'write existing ro file'    13  -- "$J" $SB -- "$TRY" write  "$TD/ro/file"
t 'create in ro dir'          13  -- "$J" $SB -- "$TRY" create "$TD/ro/new"
t 'unlink in ro dir'          13  -- "$J" $SB -- "$TRY" unlink "$TD/ro/file"
t 'mkdir in ro dir'           13  -- "$J" $SB -- "$TRY" mkdir  "$TD/ro/d"
t 'create in unlisted dir'    13  -- "$J" $SB -- "$TRY" create "$TD/deny/new"
t 'create in /tmp root'       13  -- "$J" $SB -- "$TRY" create "$TD/new"

# ===========================================================================
# 4. writing to a read-write path succeeds
# ===========================================================================
t 'write existing rw file'     0  -- "$J" $SB -- "$TRY" write  "$TD/rw/file"

# ===========================================================================
# 5. create / unlink / mkdir / rmdir in rw succeed
# ===========================================================================
t 'create in rw dir'           0  -- "$J" $SB -- "$TRY" create "$TD/rw/new"
t 'unlink in rw dir'           0  -- "$J" $SB -- "$TRY" unlink "$TD/rw/new"
t 'mkdir in rw dir'            0  -- "$J" $SB -- "$TRY" mkdir  "$TD/rw/d"
t 'rmdir in rw dir'            0  -- "$J" $SB -- "$TRY" rmdir  "$TD/rw/d"
# and the kernel really did it, observed from outside the sandbox:
[ -e "$TD/rw/new" ] && bad 'rw create+unlink round trip' 'file still exists' \
	|| ok 'rw create+unlink round trip'

# ABI 3 introduced LANDLOCK_ACCESS_FS_TRUNCATE. Before that, truncate() was
# not a gated operation at all and this assertion would be a lie.
if [ "$abi" -ge 3 ]; then
	t 'truncate ro file'  13  -- "$J" $SB -- "$TRY" trunc "$TD/ro/file"
	t 'truncate rw file'   0  -- "$J" $SB -- "$TRY" trunc "$TD/rw/file"
else
	skipt 'truncate ro file' "ABI $abi < 3, truncate not gated"
	skipt 'truncate rw file' "ABI $abi < 3, truncate not gated"
fi

# ===========================================================================
# 6. a single *file* may be granted, and that does not grant its directory
# ===========================================================================
t 'single-file grant reads'     0  -- "$J" --ro "$ROOT/t" --ro "$TD/deny/secret" \
                                      -- "$TRY" read "$TD/deny/secret"
t 'single-file grant no listing' 13 -- "$J" --ro "$ROOT/t" --ro "$TD/deny/secret" \
                                      -- "$TRY" list "$TD/deny"

# ===========================================================================
# 7. exec is gated too: a binary outside the allowlist cannot be run
# ===========================================================================
# 126 is jail's "exec refused" status; the underlying errno is EACCES.
t 'exec unlisted binary'      126  -- "$J" $SB -- /bin/sh -c true
t 'exec unlisted via probe'    13  -- "$J" $SB -- "$TRY" exec /bin/sh

# ===========================================================================
# 8. the restriction is inherited by grandchildren
# ===========================================================================
t 'child of shell: denied'     13  -- "$J" $SBSH -- /bin/sh -c \
	"exec $TRY read $TD/deny/secret"
t 'child of shell: allowed'     0  -- "$J" $SBSH -- /bin/sh -c \
	"exec $TRY read $TD/ro/file"
t 'grandchild of shell: denied' 13 -- "$J" $SBSH -- /bin/sh -c \
	"/bin/sh -c 'exec $TRY read $TD/deny/secret'"
t 'shell builtin redirect denied' 2 -- "$J" $SBSH -- /bin/sh -c \
	"echo x > $TD/deny/pwned"
[ -e "$TD/deny/pwned" ] && bad 'shell could not create denied file' 'it exists' \
	|| ok 'shell could not create denied file'

printf '\n%d passed, %d failed, %d skipped\n' "$pass" "$fail" "$skip"
[ "$fail" -eq 0 ]
