# jail

Run a command that can only touch the filesystem paths you list, using the
Linux Landlock LSM: no root, no setuid, no container.

```
jail --ro /usr --rw /tmp -- make
```

Everything not granted is denied, the restriction is inherited by every
descendant, and the command cannot take it off.

## Build

```
make          # jail, and the test probe t/try
make test
make clean
```

Pure C11, gcc, no libraries. The three Landlock syscalls are called through
`syscall(2)` directly.

## Why this exists

Landlock has been in mainline since Linux 5.13 (2021). It is the only Linux
sandboxing mechanism an unprivileged process can apply to itself: no root,
no setuid helper, no user namespace, no seccomp BPF to write, no container
runtime. It is inherited, it is irrevocable, and it costs about two hundred
lines to use.

Almost nobody uses it. The reason is not that it is hard but that it is
tedious in a specific way: there is no library worth depending on, the uapi
grows every few kernel releases, and the kernel deliberately rejects a ruleset
that mentions an access right it does not know, so every caller has to
feature-detect the ABI version by hand and decide what to do on an old
kernel. That ABI dance is most of the real work, and it is the part that never
gets exercised, because you develop on a new kernel. `jail` does it, and then
tests it (see `JAIL_ABI_MAX` below).

The result is a tool you can wrap around a build, a test suite, an unpacker, a
PDF renderer, or anything else you half-trust, on any Linux you already have.

## The oracle

The kernel is the authority. There is no mock, no stub, and nothing in the
test suite that inspects `jail`'s internals or parses its output to decide
whether a test passed.

Every assertion is a real process running under `jail` that makes a real
syscall, and the thing asserted is the kernel's own verdict. `t/try` is a
statically linked probe that performs exactly one filesystem operation and
exits `0` if it succeeded, `13` if the kernel returned EACCES, and `1` for
any other errno. "Denied" therefore cannot be confused with "the file was not
there" or "the directory was mode 000".

It is statically linked on purpose: a probe that needs no dynamic loader and
no `libc.so` means the sandbox under test has to allow only the paths the test
is actually about, so a pass is not an accident of a broad allowlist.

Ranked, the oracle checks: a denied path is EACCES; the child cannot relax its
own domain; the domain is inherited by grandchildren; read-only really is
read-only; read-write works; exec is gated too; and exit status, stdout,
stderr and stdin pass through untouched.

### `make test`

```
landlock ABI 10 on 7.2.8-200.fc44.x86_64

ok    read allowed file
ok    read allowed file in rw
ok    list allowed directory
ok    read unlisted file
ok    read /etc/passwd
ok    list unlisted directory
ok    list /
ok    list parent of granted
ok    write existing ro file
ok    create in ro dir
ok    unlink in ro dir
ok    mkdir in ro dir
ok    create in unlisted dir
ok    create in /tmp root
ok    write existing rw file
ok    create in rw dir
ok    unlink in rw dir
ok    mkdir in rw dir
ok    rmdir in rw dir
ok    rw create+unlink round trip
ok    truncate ro file
ok    truncate rw file
ok    single-file grant reads
ok    single-file grant no listing
ok    exec unlisted binary
ok    exec unlisted via probe
ok    rox: read file beneath
ok    rox: cannot list directory
ok    rox: exec beneath allowed
ok    rox on a file reads
ok    rw-no-exec: write works
ok    rw-no-exec: create works
ok    rw-no-exec: unlink works
ok    rw-no-exec: list works
ok    rw-no-exec: exec denied
ok    rw: that binary does exec
ok    child of shell: denied
ok    child of shell: allowed
ok    grandchild of shell: denied
ok    shell builtin redirect denied
ok    shell could not create denied file
ok    cannot unsandbox self
ok    cannot unsandbox via shell
      --- escape attempt transcript ---
      | note: PR_SET_NO_NEW_PRIVS 0 -> Invalid argument
      | note: restrict_self(permissive) -> success (domains only stack)
      | FAIL escape-then-read /tmp/tmp.XXXX/deny/secret errno=13(Permission denied)
ok    exit status 0 passes through
ok    exit status 42 passes through
ok    stdout exact, no jail noise
ok    stderr not merged into stdout
ok    stdin passes through
ok    signal death passes through
ok    nonexistent --ro path
ok    no command given
ok    unknown option
ok    --ro with no argument
ok    --strict accepted on new ABI
ok    no rules denies everything
ok    ABI1: still confines
ok    ABI1: rw still writable
ok    ABI1: --strict refuses
ok    ABI1: truncate NOT gated
ok    ABI1: warns on stderr
ok    deny: the subtree is withheld
ok    deny: but paths through it still resolve
ok    deny: a sibling is still granted
ok    deny: one file, not a directory
ok    deny: and rw siblings still work
ok    deny: a symlink to it is denied too
ok    deny: denying via the symlink works
ok    deny: and via a ".." path
ok    deny: a symlink to an ancestor terminates
ok    deny: the split parent cannot be listed
ok    deny: and expansion does not widen it
ok    deny: outside every grant is refused
ok    deny: a nonexistent path is refused
ok    deny: with no argument is refused
ok    no deny: a symlink out is not a grant
ok    control: granted parent exposes it
ok    200 path rules are accepted

77 passed, 0 failed, 0 skipped
```

The escape transcript is the interesting one. A child under `jail` tries to
clear `no_new_privs` (EINVAL. It is one-way) and then builds the most
permissive Landlock ruleset it can and applies it to itself. That
succeeds, and changes nothing, because Landlock domains only ever
intersect. The read is still EACCES. There is no `landlock_release_self()`,
by design.

If Landlock is missing or disabled, the harness prints why and reports every
confinement test as skipped. It never reports a pass it did not earn.

## What works

- `--ro PATH` grants read, execute and directory listing beneath `PATH`.
- `--rw PATH` additionally grants write, truncate, create, delete, rename and
  device ioctl beneath `PATH`.
- `--rox PATH` is `--ro` without directory listing: a process can run and read
  what is beneath `PATH` but cannot enumerate it. Landlock gates
  the operation and path lookup is not one, so opening a filename the process
  already knows still works. That is the intent.
- `--rw-no-exec PATH` is `--rw` without execute: a scratch directory a process
  can fill but cannot run anything out of.
- `--deny PATH` withholds a subtree from a broader grant above it:
  `--ro /home --deny /home/me/.ssh`. Landlock has no deny rule, so see below
  for how this is done and what it costs.
- `--strict` fails instead of degrading when the kernel's Landlock ABI is
  older than this build knows about, instead of silently enforcing less.
- `--abi` prints the kernel's Landlock ABI version and exits. Both are in the
  binary's own `--help` and were missing from this list.
- Paths may be single files as well as directories.
- Inherited by all descendants, across `fork` and `exec`, forever.
- Irrevocable by the sandboxed process.
- Fully transparent: `jail` `exec`s the command instead of forking it, so the
  exit status, signal death, and all three standard streams are the command's
  own by construction. Nothing here forwards them.
- Fails closed: a nonexistent `--ro`/`--rw` path, an unknown option, or an
  unavailable Landlock all exit `125` instead of running the command
  unsandboxed. `125` is reserved for `jail`'s own failures, `126`/`127` for
  exec failures, anything else is the command's.
- Graceful ABI degradation, with the missing enforcement named on stderr.

## `--deny`

Landlock cannot express it, and that was established against the kernel rather
than assumed. Two facts, measured on ABI 10:

- A rule with `allowed_access == 0` is refused with `ENOMSG`, so "deny" cannot
  be written as a rule that grants nothing.
- Rules within one ruleset are **additive, not shadowed by depth**. Granting
  `READ_FILE` on a parent and only `READ_DIR` on a child still leaves files
  under the child readable. There is no subtraction at any depth.

So `--deny` works by never granting anything that encloses the denied path. It
walks down from the grant and grants each level's *other* children
individually. The path to the denied subtree is simply never granted. One flag
becomes one rule per sibling, so the 64-rule cap had to go first.

Every child is canonicalised with `realpath` before it is considered, and only
children whose canonical path lies **strictly inside** the directory being
split are considered at all. That is not tidiness; three separate symlink
attacks work without it, and the tests for all three failed against the first
version of this code:

- A sibling symlink pointing *into* the denied subtree. The entry named `.ssh`
  is skipped, the entry named `alias` is granted, `add_path` opens with
  `O_PATH` which follows, and the denied inode is granted under another name.
- The same in reverse: `--deny alias` canonicalises to `.ssh`, the entry named
  `.ssh` is skipped, and `alias` is granted anyway.
- A symlink pointing *out* of the grant. Granting it hands over its target, so
  adding a `--deny` would make the sandbox wider than the same command
  without one. That is the worst of the three, and the reason the test asserts
  containment. Inequality on its own would pass while the sandbox got wider.

Strict containment also guarantees termination: a symlink to its own ancestor
would otherwise recurse forever.

What it costs. The directories between the grant and the denied path get no
rule of their own, so they cannot be listed. A rule on them would grant listing
of everything beneath, the denied subtree included. Traversal still works.
Landlock gates the operation and path lookup is not one, so `--ro /home --deny
/home/me/.ssh` leaves `/home/me/.bashrc` readable and `ls /home/me` denied.
The suite asserts that, because it is surprising enough to be mistaken for a
bug.

A `--deny` that falls inside no grant is refused, because it denies
nothing and is almost always a typo. Denies are global. One applies to every
grant it falls inside, wherever it sits on the command line.

## What does not work

Honestly:

- Filesystem only. No network rules, even though this kernel's ABI
  supports them. `--allow-tcp-bind`/`--allow-tcp-connect` are future work;
  today a jailed process can open any socket it likes.
- No IPC scoping. Landlock ABI 6 added `LANDLOCK_SCOPE_SIGNAL` and
  `LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET`; `jail` sets neither. A jailed process
  can signal processes outside its domain and reach abstract unix sockets.
- No seccomp, no namespaces, no rlimits, no cgroups. Landlock gates
  filesystem *access*. It does not stop a jailed process from forking, burning
  CPU, exhausting memory, or calling any syscall that is not a filesystem
  access. `jail` is a filesystem sandbox, not a general isolation layer.
- Per-ABI gaps are real. On a kernel older than ABI 3,
  `truncate()` is not a gated operation at all, so `--ro` does not prevent
  a file from being truncated to zero. The suite proves
  it: `ABI1: truncate NOT gated` is a passing test whose expectation
  is `0`, i.e. the operation succeeded. Likewise ABI < 2 has no
  `LANDLOCK_ACCESS_FS_REFER` (all cross-hierarchy rename/link is simply
  denied) and ABI < 5 cannot gate device `ioctl`s. Use `--strict` if you would
  rather not run than run with a weaker sandbox than you asked for.
- The degradation path is tested by simulation, not on an old kernel.
  `JAIL_ABI_MAX=N` clamps the detected ABI downward so the suite can drive it.
  That proves the masking logic and the warning, on the real kernel, through
  real syscalls. It does not prove the behaviour of a 5.13 kernel, which
  nothing short of a 5.13 kernel can.
- Already-open file descriptors are not restricted. Landlock checks at
  `open()`, not at `read()`/`write()`. This is why inherited stdin/stdout keep
  working, and it means any fd the command inherits is usable regardless of
  the allowlist. Do not hand a jailed process an fd you did not mean to give it.
- `--rw-no-exec` does not stop interpreted code. It gates `execve`, which
  is the only thing Landlock gates. A process that can read a file and can also
  reach an interpreter runs `python /scratch/payload.py` as a *read*, and the
  kernel has no reason to object. The flag is worth having, it closes the
  download-then-`chmod +x`-then-run path, but it is not a sandbox against
  someone who already has a working interpreter inside the allowlist.
- `--deny` costs you `ls` of the directories between the grant and the
  denied path. Explained above. It is inherent to Landlock's rules applying
  to whole subtrees. Nothing here takes a shortcut.
- `--deny` does not follow symlinks out of the grant, so those stop
  working. Without a `--deny` a symlink inside a granted tree pointing
  outside it was already useless, because the target inode was never granted.
  With one, the symlink is additionally not granted itself. The net effect is
  the same and the reason is different.
- `--deny` enumerates at startup. A directory whose contents change
  between `jail` reading it and the command running is a race. An entry created
  afterwards was never granted, so it is inaccessible, not exposed. The
  safe direction, and still a surprise.
- `--rox` is not secrecy. It stops enumeration instead of reading. Anything whose
  name can be guessed or is compiled into the attacker's payload is still
  readable. It raises the cost of reconnaissance. It does not make files
  confidential.
- `/proc` is not special-cased. If you `--ro /proc` you have granted a
  great deal. If you do not, some tools will simply break.
- Symlinks are resolved when the rule is added, not when the command runs.
  `--ro /lib` on a merged-`/usr` system grants `/usr/lib`. A symlink created
  later inside an allowed directory cannot be used to escape (the *target* is
  what gets checked at open time), but it is worth knowing which inode you
  actually granted.
- No limit worth naming on path rules, but every rule costs one open file
  descriptor at install time, so a `--deny` under a directory with tens of
  thousands of entries will meet `RLIMIT_NOFILE`. There is no check of ours.
- Cannot run under valgrind. valgrind does not implement syscall 444, so
  it returns ENOSYS and `jail` correctly refuses to run unsandboxed. The
  refusal is the right behaviour. It just makes `valgrind jail ...` useless.
- The command must be inside the allowlist, along with its shared
  libraries and the dynamic loader. `jail --rw /tmp, make` will fail to
  exec. This is not a bug, but it surprises everyone once.

## Design

One file, `jail.c`, 596 lines, 242 of them comment-only: 44% of the
non-blank lines, explaining why the kernel insists on something.

```
parse args  ->  probe ABI  ->  mask rights to ABI  ->  create ruleset
            ->  add one path_beneath rule per grant
            ->  prctl(PR_SET_NO_NEW_PRIVS)  ->  landlock_restrict_self
            ->  execvp
```

Four decisions worth naming:

`exec`, not `fork` + `wait`. The command replaces `jail` in the same
process, so there is no status to forward, no signal to re-raise, no pipe to
pump, and no way for `jail` to be a bug in the middle. Transparency is a
property of the design. No code here implements it.

`no_new_privs` before `landlock_restrict_self`. Not an ordering
preference: `restrict_self` returns EPERM without it, unless you hold
`CAP_SYS_ADMIN`, the very thing being avoided. The reason the kernel
insists: a sandboxed process that could `exec` a setuid-root binary would get
privileges it could use to act outside its domain, and Landlock's security
claim ("an unprivileged process can safely restrict itself") would be false.
`no_new_privs` is one-way and inherited, matching the domain itself.

`handled_access_fs` is masked to the detected ABI. The kernel rejects a
ruleset naming an unknown access right instead of ignoring it, so that a
program can never believe it sandboxed something the kernel did not enforce.
The cost is that the caller must do the version arithmetic. Best effort is the
default, because refusing to run on a 5.15 LTS kernel helps nobody; `--strict`
is there for when a weaker sandbox is worse than no run at all.

Rights are masked again per path type. Directory-only rights on a regular
file are an EINVAL from `landlock_add_rule`, so `--ro /etc/resolv.conf` would
fail without clamping. `O_PATH` is used to reference the inode, since we never
need to read it and `O_PATH` works on things we could not open.

The test probe is a second file only because the oracle needs a program that
reports errno numerically and depends on nothing.

## License

GPL-3.0. See `LICENSE`.
