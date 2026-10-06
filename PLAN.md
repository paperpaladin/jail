# PLAN

## Contract

`jail [--ro PATH]... [--rw PATH]... [--strict] -- CMD [ARGS...]`

Run `CMD` such that, for the whole process tree it roots, the only filesystem
paths it can read or execute are those beneath an `--ro` or `--rw` argument,
and the only paths it can write, create, delete, rename or truncate are those
beneath an `--rw` argument. Every other filesystem access is denied by the
kernel with `EACCES`.

`jail` is transparent otherwise: it `exec`s `CMD`, so the exit status, death by
signal, and stdin/stdout/stderr are `CMD`'s own and are not mediated by us.
Exit status `125` means `jail` itself failed and `CMD` never ran; `126`/`127`
mean `CMD` could not be executed; anything else came from `CMD`.

`CMD`, its shared libraries, and the dynamic loader must themselves be inside
the allowlist. Granting nothing denies everything, including exec.

On a kernel whose Landlock ABI is older than this build knows, `jail` confines
as much as that ABI permits and names the gap on stderr. `--strict` turns that
into a refusal to run. If Landlock is absent entirely, `jail` exits `125`
rather than running `CMD` unconfined.

## Hard invariant

**A path that was not granted is never accessible, and the child cannot relax
its own restrictions.**

Both halves are the kernel's to keep, not ours, and both are checked by
observing real syscalls:

1. No sequence of actions available to the sandboxed process -- including
   `fork`, `exec`, spawning a shell, spawning a shell from a shell, clearing
   `no_new_privs`, or building and applying a maximally permissive Landlock
   ruleset of its own -- makes a non-granted path accessible. Landlock domains
   only intersect; there is no syscall that removes one.
2. The `125` / `126-127` / other split on exit status is never ambiguous:
   `jail` failing is always distinguishable from `CMD` failing, so a sandbox
   that did not get applied can never be mistaken for a command that ran.

Corollary we also hold ourselves to: `jail` never runs `CMD` less confined than
the arguments asked for without saying so on stderr, and never at all under
`--strict`.

## Oracle

The kernel is the authority. Ranked by how much each would cost us to get
wrong:

1. **The child cannot drop the sandbox.** A probe clears `no_new_privs`, builds
   a permissive ruleset granting `/`, calls `landlock_restrict_self` with it --
   and then still gets `EACCES` on a denied path. If this ever passes, the tool
   is worthless.
2. **A path not in the allowlist is `EACCES`.** Not ENOENT, not EPERM, not
   "the open happened to fail". The probe reports errno numerically and the
   harness asserts on `13`.
3. **Inheritance.** A shell under `jail` is denied; a shell spawned by that
   shell is denied; a shell's own `>` redirection into a denied directory
   fails and the file does not exist afterwards.
4. **Read-only is read-only.** Write, create, unlink, mkdir and truncate
   beneath an `--ro` path all fail with `EACCES` -- truncate only where the ABI
   gates it, and the suite skips that assertion rather than lying when it does
   not.
5. **Read-write actually works.** Write, create, unlink, mkdir, rmdir succeed,
   and the created file is observed gone from outside the sandbox afterwards.
6. **Exec is gated too.** A binary outside the allowlist cannot be executed,
   and the errno is `EACCES`.
7. **Granularity.** Granting a single file does not grant its directory;
   granting two subdirectories does not grant their common parent.
8. **Transparency.** Exit `0`, exit `42`, death by `SIGTERM` (143), exact
   stdout bytes, stderr not merged into stdout, stdin piped in and read back.
9. **ABI degradation, driven for real.** `JAIL_ABI_MAX=1` forces the old-kernel
   path; confinement still holds, `--strict` refuses, the warning appears, and
   the ABI-1 truncate gap is asserted to be *present* rather than papered over.
10. **Fail-closed on our own mistakes.** Bad path, missing command, unknown
    option, missing `--ro` argument: all `125`, command never runs.

If Landlock is unavailable the harness prints the kernel version and the two
likely reasons, counts every confinement test as skipped, and exits `0`. A
skip is never dressed up as a pass.

## Non-goals

- A general isolation layer. No seccomp, no namespaces, no cgroups, no
  rlimits. Filesystem access only.
- A container runtime, an image format, or anything that mounts.
- Restricting already-open file descriptors. Landlock checks at `open()`; an
  fd the command inherits is usable. Documented, not fixed.
- A policy language, a config file, or profiles. Two flags and a path list.
- Running as root, becoming root, or dropping privileges. Unprivileged only.
- A library. One program, one job.
- Portability beyond Linux with Landlock enabled.

## Commit sequence

Eighteen commits, every one of which compiles. Granularity is for `git bisect`
and `git revert`, so a commit that does not build is worse than no commit at
all -- the one commit that fails its tests does so deliberately and is
documented below.

- [x] `Makefile`, `LICENSE`, `.gitignore`, and `jail.c` reduced to the Landlock
      ABI probe behind `--abi`.
      why: the version probe is the only feature detection Landlock offers and
      everything else is conditioned on it, so it is the one piece that cannot
      be added later. Starting here also means commit 1 already answers the
      question that decides whether the tool can work on a given kernel.
- [x] The `--ro`/`--rw` argument parser and the exec/exit-status passthrough,
      with nothing enforced yet and `--help` saying so.
      why: parsing and exec have nothing to do with Landlock and are where the
      transparency contract lives (125 is ours, 126/127 are exec, anything
      else is the command's). Judging them while no sandbox exists keeps a
      parsing bug from looking like a confinement bug.
- [x] The access-right bit groups, `abi_mask()`, `--strict`, the best-effort
      degradation warning, and ruleset creation.
      why: these four are one decision, not four. `handled_access_fs` cannot be
      chosen without knowing which bits the kernel will accept, and the kernel
      rejects an unknown bit rather than ignoring it, so the mask and the
      ruleset must land together or the intermediate state is incoherent.
- [x] `add_path()`: one `path_beneath` rule per flag, `O_PATH`, per-file-type
      right clamping, fail-closed on a bad path.
      why: separable from ruleset creation and worth isolating, because the
      two masks here are easy to confuse -- one clamps to the kernel's ABI,
      the other clamps to what a non-directory can be granted. This commit is
      also where the command-index bug enters, by adding the second loop.
- [x] `PR_SET_NO_NEW_PRIVS` followed by `landlock_restrict_self`.
      why: the ordering is a kernel requirement rather than a preference and
      deserves to be readable as its own change. This is the commit where the
      tool starts actually confining anything, and therefore the first commit
      where being wrong has consequences.
- [x] `t/try.c`, the static errno probe, and the Makefile rule that builds it.
      why: the oracle needs a program that reports errno numerically and
      depends on nothing. Landing it before the harness keeps "what we can
      observe" separate from "what we assert about it".
- [x] `t/run.sh` with the fixture, the skip path, and the first two assertion
      groups (allowed reads, denied reads). **Red: 0 passed, 8 failed.**
      why: this is the commit that found the bug, and it is left red on
      purpose. It builds, so `git bisect` still works through it; it fails,
      so the history records that the oracle caught a real defect rather than
      ratifying a working tool. Deleting that would be deleting the evidence.
- [x] Fix the command-index bug: the rule-installing loop reused the parse
      loop's index, so `jail` exec'd `--ro`. **Green: 8 passed.**
      why: kept adjacent to the red commit so the pair reads as one story and
      `git revert` of the fix reproduces the failure exactly.
- [x] Seven further assertion groups, one commit each: write gating, grant
      granularity, exec gating, inheritance by grandchildren, the escape
      attempt, transparency, and fail-closed behaviour.
      why: each group is an independent claim about the kernel, so each should
      be revertable and bisectable alone. Splitting them also means the
      message for each can say what that group proved instead of one commit
      claiming everything.
- [x] `JAIL_ABI_MAX` plus the ABI-1 degradation assertions, including the
      inverted one that expects truncation to succeed.
      why: the degradation path never runs on a modern kernel, so it was the
      largest untested claim in the repo. Making it drivable turned three
      README sentences into kernel-verified facts and exposed one real hole.
- [x] `README.md`, then `PLAN.md`, as separate commits.
      why: the transcript and the "what does not work" list are a different
      kind of artifact from the contract and the forward plan, and someone
      reverting one rarely wants to revert the other.

### Milestone 1 -- close the filesystem gaps

- [ ] `--rox PATH` (read + execute, no directory listing) and `--rw-no-exec`.
      why: "can run it but cannot enumerate it" and "can write but not run
      what it wrote" are the two access shapes people actually ask for, and
      both are single-bit changes to an existing mask.
- [ ] Explicit `--deny PATH` that shadows a broader grant.
      why: `--ro /home --deny /home/me/.ssh` is the common request. Landlock
      has no deny rules, so this must be done by granting the siblings; doing
      that correctly by hand is exactly the tedium worth hiding.
- [ ] Resolve `CMD` through `PATH` *before* restricting, and auto-grant the
      resolved binary, its interpreter, and `ldd`'s output, behind `--auto`.
      why: "the command must be in its own allowlist" is the single biggest
      usability cliff, and every new user falls off it once.
- [ ] Report the denied path on failure by parsing `dmesg`/audit when ABI 7+
      Landlock audit logging is available.
      why: `EACCES` with no indication of *which* path is the single worst part
      of debugging a Landlock policy, and the kernel now offers the answer.
- [ ] Grow past the 64-rule cap with a realloc'd array.
      why: the `shortcut:` note in `jail.c` names this; `--deny` expansion will
      blow through 64 rules on its own.
- [ ] Test the real ABI floor in CI against 5.13, 5.15 and 6.1 kernels.
      why: `JAIL_ABI_MAX` simulates the masking logic, not the kernel. Only an
      old kernel proves old-kernel behaviour, and this is the one honesty gap
      the current suite cannot close by itself.

### Milestone 2 -- beyond the filesystem

- [ ] `--allow-tcp-bind PORT` / `--allow-tcp-connect PORT` via
      `LANDLOCK_RULE_NET_PORT` (ABI 4+).
      why: this is the other half of what Landlock can do and almost nobody
      uses it either. "May read /usr, may connect to nothing" is a far more
      useful jail than filesystem rules alone.
- [ ] Default-deny all network when any `--allow-tcp-*` is given, and leave
      network untouched otherwise.
      why: silently gating network because the binary learned how to would
      break every existing invocation; opting in keeps the contract stable.
- [ ] `--scope-signal` and `--scope-unix` for `LANDLOCK_SCOPE_SIGNAL` and
      `LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET` (ABI 6+).
      why: a filesystem-confined process that can still `kill` your session or
      talk to a desktop bus over an abstract socket is not confined in the
      sense anyone means. Also requires passing the full `ruleset_attr` size,
      which the `shortcut:` note in `jail.c` flags.
- [ ] Extend the oracle to network and IPC: assert `connect()` is `EACCES` and
      a signal to a PID outside the domain fails.
      why: every rule added must come with the kernel proving it, or it is
      decoration. Same standard as the filesystem rules.
- [ ] `LANDLOCK_RESTRICT_SELF_LOG_*` flags (ABI 7+) to control audit noise.
      why: on by default is wrong for a tool run in a loop by a build system;
      off by default is wrong for a security tool. Needs a flag and a stated
      default.
- [ ] Optional `--seccomp-minimal` stacking a tiny syscall filter.
      why: named here only so the boundary stays explicit. It belongs behind a
      flag and after everything above, and it is the first thing that would
      make `jail` more than a filesystem sandbox.
