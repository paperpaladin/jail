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
	         list truncate rox-no-listing rox-exec-allowed \
	         rw-no-exec-writes rw-no-exec-denied inherit-grandchild \
	         cannot-unsandbox transparency-status transparency-stdout; do
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
# 8. --rox and --rw-no-exec: the two grants that differ by a single bit
# ===========================================================================
# --rox is --ro without READ_DIR. Section 1 already asserted that the same
# open() of the same directory succeeds under --ro, so the only thing that
# changed here is that one bit.
ROX="--rox $ROOT/t --rox $TD/ro"
t 'rox: read file beneath'       0  -- "$J" $ROX -- "$TRY" read "$TD/ro/file"
t 'rox: cannot list directory'  13  -- "$J" $ROX -- "$TRY" list "$TD/ro"
# The probe is static, so re-exec'ing it under --rox proves EXECUTE survived.
# 2 is try's own "wrong argument count" status, which it can only reach by
# having been exec'd at all.
t 'rox: exec beneath allowed'    2  -- "$J" $ROX -- "$TRY" exec "$TRY"
# READ_DIR is meaningless on a non-directory and the kernel rejects a rule
# that grants it there, so --rox on a plain file must behave like --ro.
t 'rox on a file reads'          0  -- "$J" --rox "$ROOT/t" --rox "$TD/deny/secret" \
                                       -- "$TRY" read "$TD/deny/secret"

# --rw-no-exec is --rw without EXECUTE. The target has to be genuinely
# executable or 'exec denied' would pass for the wrong reason -- a missing +x
# bit rather than Landlock -- so the identical file is also exec'd under --rw,
# where it must succeed. The same file, executable, on the same kernel: --rw
# runs it and --rw-no-exec does not. Nothing a mode bit could explain.
cp "$TRY" "$TD/rw/prog" && chmod 755 "$TD/rw/prog"
RWX="--ro $ROOT/t --rw-no-exec $TD/rw"
t 'rw-no-exec: write works'      0  -- "$J" $RWX -- "$TRY" write  "$TD/rw/file"
t 'rw-no-exec: create works'     0  -- "$J" $RWX -- "$TRY" create "$TD/rw/made"
t 'rw-no-exec: unlink works'     0  -- "$J" $RWX -- "$TRY" unlink "$TD/rw/made"
t 'rw-no-exec: list works'       0  -- "$J" $RWX -- "$TRY" list   "$TD/rw"
t 'rw-no-exec: exec denied'     13  -- "$J" $RWX -- "$TRY" exec   "$TD/rw/prog"
t 'rw: that binary does exec'    2  -- "$J" $SB  -- "$TRY" exec   "$TD/rw/prog"

# ===========================================================================
# 9. the restriction is inherited by grandchildren
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

# ===========================================================================
# 10. the child CANNOT drop the restriction  <- Landlock's whole promise
# ===========================================================================
t 'cannot unsandbox self'      13  -- "$J" $SB -- "$TRY" escape "$TD/deny/secret"
t 'cannot unsandbox via shell'  13 -- "$J" $SBSH -- /bin/sh -c \
	"exec $TRY escape $TD/deny/secret"
# Show the attempts for the record; this is the one place we read stdout, and
# only to print it, not to decide anything.
printf '      --- escape attempt transcript ---\n'
"$J" $SB -- "$TRY" escape "$TD/deny/secret" 2>&1 | sed 's/^/      | /'

# ===========================================================================
# 11. transparency: exit status and stdout pass through unchanged
# ===========================================================================
tout 'exit status 0 passes through'   0  'hi'   -- "$J" $SBSH -- /bin/sh -c 'echo hi'
tout 'exit status 42 passes through' 42  ''     -- "$J" $SBSH -- /bin/sh -c 'exit 42'
tout 'stdout exact, no jail noise'    0  'a
b'  -- "$J" $SBSH -- /bin/sh -c 'echo a; echo b'
tout 'stderr not merged into stdout'  0  'O'    -- "$J" $SBSH -- /bin/sh -c \
	'echo O; echo E >&2'
# Already-open fds survive: Landlock checks at open() time, so inherited
# stdin works even though /dev and the pipe's path are not in the allowlist.
_o=$(printf 'abc' | "$J" $SBSH -- /bin/cat 2>/dev/null)
[ "$_o" = abc ] && ok 'stdin passes through' \
	|| bad 'stdin passes through' "got [$_o]"
# Death by signal is the child's own, because jail execs rather than forks.
"$J" $SBSH -- /bin/sh -c 'kill -TERM $$' 2>/dev/null
[ $? -eq 143 ] && ok 'signal death passes through' \
	|| bad 'signal death passes through' "got $?"

# ===========================================================================
# 12. jail fails closed on its own mistakes (125, distinct from any child)
# ===========================================================================
t 'nonexistent --ro path'     125  -- "$J" --ro /nonexistent-xyz -- /bin/true
t 'no command given'          125  -- "$J" --ro /usr
t 'unknown option'            125  -- "$J" --bogus -- /bin/true
t '--ro with no argument'     125  -- "$J" --ro
if [ "$abi" -ge 5 ]; then
	t '--strict accepted on new ABI' 0 -- "$J" --strict $SBSH -- /bin/sh -c true
else
	t '--strict refuses old ABI'   125 -- "$J" --strict $SBSH -- /bin/sh -c true
fi
# Zero rules means zero access -- the degenerate case must still be coherent.
t 'no rules denies everything' 126  -- "$J" -- /bin/sh -c true

# The rule array used to be a fixed 64 with a refusal past it, which was fine
# while every rule came from a flag someone typed. 200 of them must work now,
# because --deny expands one flag into one rule per sibling and a directory
# with a few hundred entries is ordinary.
many=""
n=0
while [ $n -lt 200 ]; do many="$many --ro $ROOT/t"; n=$((n + 1)); done
t '200 path rules are accepted'  0  -- "$J" $many -- "$TRY" read "$ROOT/t/try.c"

# ===========================================================================
# 13. the ABI degradation path, forced with JAIL_ABI_MAX
# ===========================================================================
# This is the part of any Landlock program most likely to be wrong, because on
# a current kernel it never runs. Clamping down lets the kernel judge it too.
if [ "$abi" -gt 1 ]; then
	t 'ABI1: still confines'     13 -- env JAIL_ABI_MAX=1 \
		"$J" $SB -- "$TRY" read "$TD/deny/secret"
	t 'ABI1: rw still writable'   0 -- env JAIL_ABI_MAX=1 \
		"$J" $SB -- "$TRY" write "$TD/rw/file"
	t 'ABI1: --strict refuses'  125 -- env JAIL_ABI_MAX=1 \
		"$J" --strict $SB -- "$TRY" read "$TD/ro/file"
	# The honest part: at ABI 1 truncate() is not a gated operation, so a
	# read-only grant does NOT stop truncation. The oracle confirms the
	# gap rather than the README merely claiming it.
	t 'ABI1: truncate NOT gated'  0 -- env JAIL_ABI_MAX=1 \
		"$J" $SB -- "$TRY" trunc "$TD/ro/file"
	echo readable > "$TD/ro/file"   # undo it for anyone reading after us
	# And the degradation is announced, not silent.
	if env JAIL_ABI_MAX=1 "$J" $SB -- "$TRY" read "$TD/ro/file" 2>&1 \
	   >/dev/null | grep -q 'warning: landlock ABI 1, degrading'; then
		ok 'ABI1: warns on stderr'
	else
		bad 'ABI1: warns on stderr' 'no warning seen'
	fi
else
	for n in 'ABI1: still confines' 'ABI1: rw still writable' \
	         'ABI1: --strict refuses' 'ABI1: truncate NOT gated' \
	         'ABI1: warns on stderr'; do
		skipt "$n" "kernel is already ABI 1"
	done
fi

printf '\n%d passed, %d failed, %d skipped\n' "$pass" "$fail" "$skip"
[ "$fail" -eq 0 ]
