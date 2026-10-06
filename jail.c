/*
 * jail - unprivileged filesystem sandbox via the Linux Landlock LSM.
 *
 *   jail --ro /usr --rw /tmp -- CMD ARGS...
 *
 * No root, no setuid, no namespaces, no container. We ask the kernel to
 * permanently narrow what *this* process (and every descendant) may touch on
 * the filesystem, then exec the command. The kernel enforces it; we are not
 * in the loop afterwards.
 *
 * Copyright (C) 2026  PLACEHOLDER.  Licensed under the GPLv3 (see LICENSE).
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/landlock.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

/*
 * Landlock's uapi grew over time and distro headers lag behind running
 * kernels. Define what we use if the build host's headers predate it; the
 * numeric values are ABI, frozen forever by the kernel's compatibility rules.
 */
#ifndef LANDLOCK_ACCESS_FS_REFER
#define LANDLOCK_ACCESS_FS_REFER (1ULL << 13)
#endif
#ifndef LANDLOCK_ACCESS_FS_TRUNCATE
#define LANDLOCK_ACCESS_FS_TRUNCATE (1ULL << 14)
#endif
#ifndef LANDLOCK_ACCESS_FS_IOCTL_DEV
#define LANDLOCK_ACCESS_FS_IOCTL_DEV (1ULL << 15)
#endif

/*
 * The three Landlock syscalls. There is no glibc wrapper for them (and no
 * liblandlock worth a dependency), so we go through syscall(2) directly.
 */
static inline int ll_create_ruleset(const struct landlock_ruleset_attr *attr,
                                    size_t size, uint32_t flags) {
	return (int)syscall(SYS_landlock_create_ruleset, attr, size, flags);
}
static inline int ll_add_rule(int fd, enum landlock_rule_type type,
                              const void *attr, uint32_t flags) {
	return (int)syscall(SYS_landlock_add_rule, fd, type, attr, flags);
}
static inline int ll_restrict_self(int fd, uint32_t flags) {
	return (int)syscall(SYS_landlock_restrict_self, fd, flags);
}

/*
 * What each bit means, because the names are terse and the grouping matters:
 *
 *   EXECUTE      execve() a file in this hierarchy
 *   READ_FILE    open() a file for reading
 *   READ_DIR     opendir()/getdents() - *listing* a directory, which is a
 *                separate right from traversing it (traversal is always
 *                allowed; Landlock gates the operations, not the lookup)
 *   WRITE_FILE   open() a file for writing
 *   TRUNCATE     truncate()/ftruncate()/O_TRUNC  (ABI 3+)
 *   IOCTL_DEV    ioctl() on an opened character or block device  (ABI 5+)
 *   REMOVE_*     unlink()/rmdir(), and rename's "source side"
 *   MAKE_*       create a file of that type: REG regular, DIR directory, SYM
 *                symlink, FIFO named pipe, SOCK unix socket, CHAR/BLOCK device
 *                nodes (device nodes still need CAP_MKNOD, this right is not
 *                a privilege grant)
 *   REFER        link()/rename() *across* two different allowed hierarchies.
 *                Special: when REFER is not in handled_access_fs the kernel
 *                denies all cross-hierarchy link/rename unconditionally, so
 *                handling it is strictly more permissive, not less. (ABI 2+)
 */
#define JAIL_FS_READ (                      \
	LANDLOCK_ACCESS_FS_EXECUTE |        \
	LANDLOCK_ACCESS_FS_READ_FILE |      \
	LANDLOCK_ACCESS_FS_READ_DIR)

#define JAIL_FS_WRITE (                     \
	LANDLOCK_ACCESS_FS_WRITE_FILE |     \
	LANDLOCK_ACCESS_FS_REMOVE_DIR |     \
	LANDLOCK_ACCESS_FS_REMOVE_FILE |    \
	LANDLOCK_ACCESS_FS_MAKE_CHAR |      \
	LANDLOCK_ACCESS_FS_MAKE_DIR |       \
	LANDLOCK_ACCESS_FS_MAKE_REG |       \
	LANDLOCK_ACCESS_FS_MAKE_SOCK |      \
	LANDLOCK_ACCESS_FS_MAKE_FIFO |      \
	LANDLOCK_ACCESS_FS_MAKE_BLOCK |     \
	LANDLOCK_ACCESS_FS_MAKE_SYM |       \
	LANDLOCK_ACCESS_FS_REFER |          \
	LANDLOCK_ACCESS_FS_TRUNCATE |       \
	LANDLOCK_ACCESS_FS_IOCTL_DEV)

/*
 * Rights that are meaningless on a non-directory. The kernel rejects a rule
 * with EINVAL if it grants a directory-only right on a regular file, so a
 * plain `--ro /etc/resolv.conf` would fail unless we mask. Everything not
 * listed here is directory-only.
 */
#define JAIL_FS_FILE_OK (                   \
	LANDLOCK_ACCESS_FS_EXECUTE |        \
	LANDLOCK_ACCESS_FS_WRITE_FILE |     \
	LANDLOCK_ACCESS_FS_READ_FILE |      \
	LANDLOCK_ACCESS_FS_TRUNCATE |       \
	LANDLOCK_ACCESS_FS_IOCTL_DEV)

/* The highest ABI this program knows how to use. */
#define JAIL_ABI_KNOWN 5

static const char *prog = "jail";

static void die(const char *what) {
	fprintf(stderr, "%s: %s: %s\n", prog, what, strerror(errno));
	exit(125); /* 125: jail itself failed, distinct from any child status */
}

static void usage(FILE *f) {
	fprintf(f,
	    "usage: %s [--ro PATH]... [--rw PATH]... [--strict] -- CMD [ARGS...]\n"
	    "\n"
	    "  --ro PATH   allow read and execute beneath PATH\n"
	    "  --rw PATH   allow read, execute, write, create and delete beneath PATH\n"
	    "  --strict    fail instead of degrading when the kernel's Landlock ABI\n"
	    "              is older than this build knows about\n"
	    "  --abi       print the kernel's Landlock ABI version and exit\n"
	    "\n"
	    "Anything not granted is denied: the kernel returns EACCES. The\n"
	    "restriction is inherited by all descendants and cannot be removed.\n"
	    "CMD must itself live under an --ro/--rw path, as must its shared\n"
	    "libraries and the dynamic loader.\n",
	    prog);
}

/*
 * Drop the ABI bits the running kernel does not have. Landlock refuses a
 * ruleset whose handled_access_fs contains an unknown bit (EINVAL) rather
 * than silently ignoring it -- deliberate, so a program cannot *think* it
 * sandboxed something the kernel never enforced. The flip side is that every
 * caller must do this dance by hand. Best-effort mode is the honest default:
 * on an old kernel you get weaker confinement, and we say so on stderr.
 */
static uint64_t abi_mask(int abi) {
	uint64_t m = ~0ULL;
	if (abi < 5) m &= ~LANDLOCK_ACCESS_FS_IOCTL_DEV;
	if (abi < 3) m &= ~LANDLOCK_ACCESS_FS_TRUNCATE;
	if (abi < 2) m &= ~LANDLOCK_ACCESS_FS_REFER;
	return m;
}

/* Grant `rights` beneath `path`, clamped to what makes sense for its type. */
static void add_path(int ruleset, const char *path, uint64_t rights) {
	struct landlock_path_beneath_attr pb = {0};
	struct stat st;

	/*
	 * O_PATH: we only need the fd as a reference to the inode, we are not
	 * reading it, and O_PATH works on things we could not open normally
	 * (directories we lack read on, device nodes, dangling mount points).
	 */
	pb.parent_fd = open(path, O_PATH | O_CLOEXEC);
	if (pb.parent_fd < 0) {
		fprintf(stderr, "%s: %s: %s\n", prog, path, strerror(errno));
		/*
		 * Fail closed on a bad path. A typo in --rw would otherwise
		 * silently become "deny", and the user would debug the wrong
		 * thing for an hour.
		 */
		exit(125);
	}
	if (fstat(pb.parent_fd, &st) < 0) die(path);

	pb.allowed_access = rights;
	if (!S_ISDIR(st.st_mode)) pb.allowed_access &= JAIL_FS_FILE_OK;

	if (ll_add_rule(ruleset, LANDLOCK_RULE_PATH_BENEATH, &pb, 0) < 0)
		die(path);
	close(pb.parent_fd);
}

int main(int argc, char **argv) {
	/* Parsed rules, in order. shortcut: fixed cap, grow to a realloc'd
	 * array if anyone ever needs more than 64 path rules. */
	struct { const char *path; uint64_t rights; } rule[64];
	int nrule = 0, strict = 0, i, cmd;
	int abi, ruleset;
	uint64_t handled, mask;
	struct landlock_ruleset_attr attr = {0};

	if (argv[0]) prog = argv[0];

	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--")) { i++; break; }
		if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
			usage(stdout);
			return 0;
		}
		if (!strcmp(argv[i], "--strict")) { strict = 1; continue; }
		if (!strcmp(argv[i], "--abi")) {
			abi = ll_create_ruleset(NULL, 0,
			    LANDLOCK_CREATE_RULESET_VERSION);
			if (abi < 0) {
				printf("0\n"); /* unavailable */
				return 1;
			}
			printf("%d\n", abi);
			return 0;
		}
		if (!strcmp(argv[i], "--ro") || !strcmp(argv[i], "--rw")) {
			if (i + 1 >= argc) {
				fprintf(stderr, "%s: %s needs a PATH\n", prog,
				    argv[i]);
				return 125;
			}
			if (nrule == (int)(sizeof rule / sizeof *rule)) {
				fprintf(stderr, "%s: too many path rules\n", prog);
				return 125;
			}
			rule[nrule].rights = (argv[i][3] == 'w')
			    ? (JAIL_FS_READ | JAIL_FS_WRITE) : JAIL_FS_READ;
			rule[nrule].path = argv[++i];
			nrule++;
			continue;
		}
		fprintf(stderr, "%s: unknown option: %s\n", prog, argv[i]);
		usage(stderr);
		return 125;
	}
	/* Hold the command's index in its own variable: `i` is reused below as
	 * a loop counter, and conflating the two cost an hour once already. */
	cmd = i;
	if (cmd >= argc) {
		fprintf(stderr, "%s: no command given\n", prog);
		usage(stderr);
		return 125;
	}

	/*
	 * Ask the kernel which ABI it speaks. This is the only supported
	 * feature-detection mechanism: there is no /sys knob listing the
	 * individual access rights, so "create a ruleset with flag VERSION and
	 * no attr" is how you probe.
	 */
	abi = ll_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
	if (abi < 0) {
		/*
		 * ENOSYS: kernel without Landlock compiled in.
		 * EOPNOTSUPP: compiled in but not enabled (missing from
		 * lsm= on the kernel command line).
		 */
		fprintf(stderr,
		    "%s: landlock unavailable (%s); refusing to run unsandboxed\n",
		    prog, strerror(errno));
		return 125;
	}

	mask = abi_mask(abi);
	if (abi < JAIL_ABI_KNOWN) {
		if (strict) {
			fprintf(stderr,
			    "%s: landlock ABI %d < %d and --strict given\n",
			    prog, abi, JAIL_ABI_KNOWN);
			return 125;
		}
		/* Best effort: say exactly what is not being enforced. */
		fprintf(stderr,
		    "%s: warning: landlock ABI %d, degrading (no%s%s%s)\n",
		    prog, abi,
		    abi < 2 ? " cross-hierarchy-rename-control" : "",
		    abi < 3 ? " truncate-control" : "",
		    abi < 5 ? " device-ioctl-control" : "");
	}

	/*
	 * handled_access_fs is the set of operations this ruleset *decides*.
	 * Anything not handled is left entirely to the rest of the kernel --
	 * so handling more is stricter, and a right we handle but never grant
	 * is thereby denied everywhere.
	 */
	handled = (JAIL_FS_READ | JAIL_FS_WRITE) & mask;
	attr.handled_access_fs = handled;

	/*
	 * Pass the size of the struct we know; the kernel uses it to tell
	 * which fields exist (extensible-struct convention). Our struct may be
	 * larger than an old kernel expects, so clamp to the fields we set --
	 * handled_access_fs only. shortcut: bump this when we start setting
	 * handled_access_net or scoped; see PLAN.md Milestone 2.
	 */
	ruleset = ll_create_ruleset(&attr, sizeof(attr.handled_access_fs), 0);
	if (ruleset < 0) die("landlock_create_ruleset");

	for (i = 0; i < nrule; i++)
		add_path(ruleset, rule[i].path, rule[i].rights & mask);

	/*
	 * no_new_privs MUST be set before landlock_restrict_self, which
	 * otherwise fails with EPERM (unless we have CAP_SYS_ADMIN, which we
	 * deliberately do not). The reason: without it a sandboxed process
	 * could exec a setuid-root binary and have the kernel hand it
	 * privileges it could use to look outside the sandbox. Landlock's
	 * whole security claim is "an unprivileged process can restrict
	 * itself", and that only holds if it cannot gain privileges
	 * afterwards. no_new_privs is also one-way and inherited, same as the
	 * Landlock domain itself.
	 */
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0)
		die("prctl(PR_SET_NO_NEW_PRIVS)");

	/*
	 * The point of no return. The ruleset becomes a "domain" attached to
	 * this task, inherited across fork and exec. A later restrict_self
	 * only *intersects* with it: domains stack, they never widen. There is
	 * no syscall to remove one, and nothing short of task exit clears it.
	 */
	if (ll_restrict_self(ruleset, 0) < 0) die("landlock_restrict_self");
	close(ruleset);

	/*
	 * exec, not fork+exec: the child *is* this process, so its exit status
	 * and signal death are ours by construction and already-open fds
	 * (stdin/stdout/stderr, any redirection the caller set up) keep
	 * working -- Landlock checks at open() time, not on read()/write().
	 * That is the whole transparency story, and it costs zero code.
	 */
	execvp(argv[cmd], &argv[cmd]);
	fprintf(stderr, "%s: exec %s: %s\n", prog, argv[cmd], strerror(errno));
	/* Shell convention, so callers can tell exec failure from a real exit. */
	return errno == ENOENT ? 127 : 126;
}
