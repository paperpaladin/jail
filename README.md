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

The kernel is the authority. There is no mock and no stub, and only three
assertions in the whole suite read anything `jail` printed instead of asking
the kernel: the ABI-1 degradation warning, the `--auto` grant report, and the
`--auto` resolution cases. The first two are claims about a message, so a
message is the only thing that can check them. The third has a different
authority rather than no authority: *which* file a `PATH` lookup picks is
glibc's business, not the kernel's, so each of those cases runs the same
`PATH` and the same working directory through `env`(1), which is a thin
wrapper around `execvp(3)`, and demands that `jail` and glibc agree with each
other and with the answer written in the test.

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
ok    control: granted parent exposes it
ok    deny: the subtree is withheld
ok    deny: a sibling is still granted
ok    deny: and rw siblings still work
ok    deny: one file, not a directory
ok    deny: a symlink to it is denied too
ok    deny: denying via the symlink works
ok    deny: and via a ".." path
ok    no deny: a symlink out is not a grant
ok    deny: and expansion does not widen it
ok    deny: a symlink to an ancestor terminates
ok    deny: the split parent cannot be listed
ok    deny: but paths through it still resolve
ok    deny: outside every grant is refused
ok    deny: a nonexistent path is refused
ok    deny: with no argument is refused
ok    auto: found through PATH
ok    auto: first match wins
ok    auto: non-executable is skipped
ok    auto: a directory is skipped
ok    auto: a slash means no PATH lookup
ok    auto: ./missing is 127
ok    auto: empty element is the cwd
ok    auto: trailing empty element too
ok    auto: no such name is 127
ok    auto: found but not executable is 126
ok    auto: refuses the ENOEXEC-to-sh fallback
ok    auto: unset PATH is not the cwd
ok    auto: a dynamic command runs
ok    control: without --auto it cannot
ok    auto: the library is readable
ok    auto: the library is NOT executable
ok    control: the library is executable at all
ok    auto: the library directory is not listable
ok    auto: /usr/bin is not listable
ok    auto: a sibling binary cannot run
ok    auto: /etc/passwd is still denied
ok    auto: the grants are named on stderr
ok    auto: a static command needs only itself
ok    control: the same without --auto
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
ok    200 path rules are accepted
ok    ABI1: still confines
ok    ABI1: rw still writable
ok    ABI1: --strict refuses
ok    ABI1: truncate NOT gated
ok    ABI1: warns on stderr

101 passed, 0 failed, 0 skipped
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
- `--auto` resolves `CMD` through `PATH` before the sandbox is installed and
  grants the three things needed to run it: the resolved binary, its dynamic
  loader, and each shared library. Nothing else, and every one of them is
  printed on stderr. See below for exactly what that is and what it is not.
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

## `--auto`

The single biggest usability cliff in this tool is that `CMD` has to be inside
its own allowlist, together with its loader and its libraries, and everyone
falls off it once. `--auto` does that resolution before anything is enforced.

Auto-granting is in direct tension with the point of the program, so this is
the exhaustive list of what it grants, with the rights it grants:

| what | rights | why |
| --- | --- | --- |
| the resolved `CMD` | `EXECUTE`, `READ_FILE` | `execve` opens it with `FMODE_EXEC`, which Landlock reads as a demand for both |
| the dynamic loader (`PT_INTERP`) | `EXECUTE`, `READ_FILE` | the kernel opens it the same way, through `open_exec` |
| each shared library `ldd` resolves | `READ_FILE` | the loader `open`s it `O_RDONLY` and `mmap`s it, and Landlock has no `mmap` hook |

Each one is granted as a single file. No directory is ever granted, and the
rights are per entry rather than one mask for the lot. The suite asserts the
difference in both directions, because "the command ran" proves the grant was
*sufficient* and says nothing about whether it was *minimal*:

- the command runs, and without `--auto` the identical command cannot be
  exec'd at all;
- `libc.so.6` is readable, and `execve` of it is `EACCES` -- with the control
  that the same `execve` of the same file succeeds unconfined, so the denial
  is Landlock's and not a missing mode bit;
- the directory the libraries live in cannot be listed, and neither can
  `/usr/bin`;
- `/bin/cat` cannot be exec'd even though it needs exactly the loader and the
  libc that were just granted. The grant was of `/bin/sh`, not of the
  directory it sits in.

Every path is named on stderr before the command starts:

```
$ jail --auto -- /bin/echo hi
jail: --auto: exec+read /usr/bin/echo
jail: --auto: read /usr/lib/x86_64-linux-gnu/libc.so.6
jail: --auto: exec+read /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
hi
```

That report is part of the contract, not decoration: a sandbox that widens
itself silently is worse than one that refuses.

### Which `execvp` behaviours this reproduces

Resolution order is observable, and guessing at it would mean granting one
path and running another. These are reproduced, and each has a test that
compares `jail --auto` against `env`(1):

- a name containing a `/` is used as given and `PATH` is never consulted;
- the first element that holds a regular, executable file wins;
- a match that cannot be executed does **not** end the search: `execvp` tries
  it, gets `EACCES`, remembers that, and keeps walking the list, so
  `PATH=/noexec:/good` still runs `/good/cmd`. A directory of the right name
  is skipped the same way;
- an empty element means the current directory, leading, trailing or in the
  middle;
- an unset `PATH` is not an empty `PATH`: glibc falls back to
  `confstr(_CS_PATH)`, which is `/bin:/usr/bin`. Reading it as empty would
  search the current directory, which is both wrong and the dangerous
  direction to be wrong in;
- nothing of that name is `127`; found but not executable is `126`.

One behaviour is deliberately **refused**. A file that is regular and
executable but not a valid executable makes `execve` fail with `ENOEXEC`, and
glibc answers that by re-running the file through `/bin/sh`. `jail --auto`
does not: quietly pulling an interpreter into a sandbox the user did not ask
to grant it in is the one thing this flag must never do. It exits `126` with
`Exec format error`. The test measures both halves -- `env` runs the file,
`jail` refuses -- so this cannot rot back into `execvp` unnoticed.

The lookup approximates "try `execve` and keep going" with `stat` plus
`access(X_OK)`. Across the eleven cases in the suite that is the same answer
glibc gives, including the one where the candidate is a directory.

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
  afterwards was never granted, so it is inaccessible and nothing leaks. The
  safe direction, and still a surprise.
- `--rox` is not secrecy. It stops enumeration instead of reading. Anything whose
  name can be guessed or is compiled into the attacker's payload is still
  readable. It raises the cost of reconnaissance. It does not make files
  confidential.
- `/proc` is not special-cased. If you `--ro /proc` you have granted a
  great deal. If you do not, some tools will simply break.
- Symlinks are resolved when the rule is added, before the command ever runs.
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
  exec. This is not a bug, but it surprises everyone once. `--auto` is the
  answer to it, and is opt-in rather than the default, because a flag that
  grants paths nobody typed should be asked for.
- `--auto` shells out to `ldd`, and inherits two things from it. If `ldd` is
  missing or fails, `jail` says so on stderr and grants only what it did
  list, so the command fails at exec rather than anything being widened to
  cover the doubt. And `ldd` on a binary you do not trust can run it:
  `--auto` is a convenience for commands you chose, not armour against one
  you did not. Resolving `DT_NEEDED`, `ld.so.cache`, `RPATH` and `RUNPATH` by
  hand would avoid that, and would also be a reimplementation of the loader's
  search order, where being subtly wrong means granting a path the loader
  does not use while the one it does use stays denied.
- `--auto` grants nothing a program needs at *runtime*: no config, no data
  files, no `/etc/resolv.conf`, no locale archive, no `/proc`, no plugins it
  dlopens later. It grants what is needed to *start* the process, and a tool
  that needs more still needs `--ro` and `--rw` for it.
- `--auto` does not read a `#!` line. A script resolved through `PATH` is
  granted, and then the kernel execs the interpreter named in its shebang,
  which is not granted, so the run fails with `EACCES`. Grant the interpreter
  yourself, or run `jail --auto -- python3 script.py`, where the command
  really is the binary.
- `--auto` resolves the command once and execs the path it resolved, so a
  symlinked name (`/bin/sh` to `dash`) is followed here rather than at exec
  time. `argv[0]` is still what the user typed.
- `--deny` applies to `--auto` grants, which is coherent but easy to use
  accidentally: `--auto --deny` on the libc it just granted is a command that
  cannot start, and the kernel says so through the loader rather than through
  us. The stderr report names what `--auto` asked for, so a `--deny` landing
  on one of those paths makes the report an overstatement.

## Design

One file, `jail.c`, 770 lines, 310 of them comment-only: 43% of the
non-blank lines, explaining why the kernel insists on something.

```
parse args  ->  (--auto: resolve CMD through PATH, ask ldd, grant those)
            ->  probe ABI  ->  mask rights to ABI  ->  create ruleset
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
Its cost is that the caller must do the version arithmetic. Best effort is the
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
