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

static const char *prog = "jail";

static void usage(FILE *f) {
	fprintf(f,
	    "usage: %s [--ro PATH]... [--rw PATH]... -- CMD [ARGS...]\n"
	    "\n"
	    "  --ro PATH   allow read and execute beneath PATH\n"
	    "  --rw PATH   allow read, execute, write, create and delete beneath PATH\n"
	    "  --abi       print the kernel's Landlock ABI version and exit\n"
	    "\n"
	    "NOTE: nothing is enforced yet -- the Landlock ruleset is not built\n"
	    "until the next two commits. Argument handling and the exec/exit-status\n"
	    "passthrough land first so each can be judged on its own.\n"
	    "\n"
	    "Anything not granted is denied: the kernel returns EACCES. The\n"
	    "restriction is inherited by all descendants and cannot be removed.\n"
	    "CMD must itself live under an --ro/--rw path, as must its shared\n"
	    "libraries and the dynamic loader.\n",
	    prog);
}

int main(int argc, char **argv) {
	/* Parsed rules, in order. shortcut: fixed cap, grow to a realloc'd
	 * array if anyone ever needs more than 64 path rules. */
	struct { const char *path; uint64_t rights; } rule[64];
	int nrule = 0, i;
	int abi;

	if (argv[0]) prog = argv[0];

	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--")) { i++; break; }
		if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
			usage(stdout);
			return 0;
		}
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
	if (i >= argc) {
		fprintf(stderr, "%s: no command given\n", prog);
		usage(stderr);
		return 125;
	}

	/*
	 * exec, not fork+exec: the child *is* this process, so its exit status
	 * and signal death are ours by construction and already-open fds
	 * (stdin/stdout/stderr, any redirection the caller set up) keep
	 * working -- Landlock checks at open() time, not on read()/write().
	 * That is the whole transparency story, and it costs zero code.
	 */
	execvp(argv[i], &argv[i]);
	fprintf(stderr, "%s: exec %s: %s\n", prog, argv[i], strerror(errno));
	/* Shell convention, so callers can tell exec failure from a real exit. */
	return errno == ENOENT ? 127 : 126;
}
