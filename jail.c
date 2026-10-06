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
#include <linux/landlock.h>
#include <stdint.h>
#include <stdio.h>
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

static const char *prog = "jail";

static void usage(FILE *f) {
	fprintf(f,
	    "usage: %s --abi\n"
	    "\n"
	    "  --abi   print the kernel's Landlock ABI version (0 if unavailable)\n"
	    "\n"
	    "Sandboxing is not implemented yet. This commit establishes the only\n"
	    "feature detection Landlock offers, which everything else depends on.\n",
	    prog);
}

int main(int argc, char **argv) {
	int abi;

	if (argv[0]) prog = argv[0];

	if (argc == 2 && (!strcmp(argv[1], "-h") || !strcmp(argv[1], "--help"))) {
		usage(stdout);
		return 0;
	}
	if (argc == 2 && !strcmp(argv[1], "--abi")) {
		/*
		 * The only supported way to ask what Landlock can do: there is
		 * no /sys knob enumerating the individual access rights, so
		 * "create a ruleset with flag VERSION and no attr" is the
		 * probe. A negative return means Landlock is not usable --
		 * ENOSYS when it was not compiled in, EOPNOTSUPP when it was
		 * but is missing from the kernel's lsm= list.
		 */
		abi = ll_create_ruleset(NULL, 0,
		    LANDLOCK_CREATE_RULESET_VERSION);
		if (abi < 0) {
			printf("0\n");
			return 1;
		}
		printf("%d\n", abi);
		return 0;
	}
	usage(stderr);
	return 125;
}
