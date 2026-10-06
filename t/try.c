/*
 * try - the oracle's probe. Attempt one filesystem syscall and report what
 * the kernel actually said, by errno, on stdout.
 *
 *   try OP PATH          OP: read write create unlink mkdir rmdir list trunc
 *                            exec escape
 *
 * Exit status is the point: 0 = the syscall succeeded, 13 = the kernel
 * returned EACCES (Landlock denied it), 1 = some other errno. The test
 * harness asserts on that number, so "denied" can never be confused with
 * "the file happened not to exist".
 *
 * Built -static on purpose: a probe that needs no loader and no libc.so keeps
 * the allowlist under test down to exactly the paths the test is about.
 *
 * Copyright (C) 2026  PLACEHOLDER.  Licensed under the GPLv3 (see LICENSE).
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/landlock.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

static int done(const char *op, const char *path, int r) {
	if (r >= 0) {
		printf("OK %s %s\n", op, path);
		return 0;
	}
	printf("FAIL %s %s errno=%d(%s)\n", op, path, errno, strerror(errno));
	return errno == EACCES ? 13 : 1;
}

/*
 * Try every unprivileged trick to get out, then touch the denied path. If
 * Landlock is what it claims, the final open() is still EACCES.
 */
static int escape(const char *path) {
	struct landlock_ruleset_attr attr = {0};
	struct landlock_path_beneath_attr pb = {0};
	int rs, fd;

	/* 1. no_new_privs is one-way; clearing it is not a thing. */
	if (prctl(PR_SET_NO_NEW_PRIVS, 0, 0, 0, 0) == 0)
		printf("note: PR_SET_NO_NEW_PRIVS 0 returned success\n");
	else
		printf("note: PR_SET_NO_NEW_PRIVS 0 -> %s\n", strerror(errno));

	/*
	 * 2. Build the most permissive ruleset we can and self-apply it.
	 *    This *succeeds*, and changes nothing: a new domain intersects
	 *    with the inherited one. There is no landlock_release_self().
	 */
	attr.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE;
	rs = (int)syscall(SYS_landlock_create_ruleset, &attr,
	    sizeof(attr.handled_access_fs), 0);
	if (rs < 0) {
		printf("note: create_ruleset -> %s\n", strerror(errno));
	} else {
		pb.parent_fd = open("/", O_PATH | O_CLOEXEC);
		pb.allowed_access = LANDLOCK_ACCESS_FS_READ_FILE;
		if (pb.parent_fd >= 0 &&
		    syscall(SYS_landlock_add_rule, rs,
		        LANDLOCK_RULE_PATH_BENEATH, &pb, 0) < 0)
			printf("note: add_rule / -> %s\n", strerror(errno));
		if (pb.parent_fd >= 0) close(pb.parent_fd);
		printf("note: restrict_self(permissive) -> %s\n",
		    syscall(SYS_landlock_restrict_self, rs, 0) == 0
		        ? "success (domains only stack)" : strerror(errno));
		close(rs);
	}

	/* 3. The verdict. */
	fd = open(path, O_RDONLY);
	if (fd >= 0) close(fd);
	return done("escape-then-read", path, fd);
}

int main(int argc, char **argv) {
	const char *op, *path;
	int fd, r;

	if (argc != 3) {
		fprintf(stderr, "usage: %s OP PATH\n", argv[0]);
		return 2;
	}
	op = argv[1];
	path = argv[2];

	if (!strcmp(op, "read") || !strcmp(op, "list")) {
		/* list opens with O_DIRECTORY, which needs READ_DIR, not
		 * READ_FILE -- distinct Landlock rights, worth probing apart. */
		fd = open(path, O_RDONLY | (op[0] == 'l' ? O_DIRECTORY : 0));
		if (fd >= 0) close(fd);
		return done(op, path, fd);
	}
	if (!strcmp(op, "write")) {
		fd = open(path, O_WRONLY);
		if (fd >= 0) {
			r = (int)write(fd, "x", 1);
			close(fd);
			if (r < 0) return done(op, path, r);
		}
		return done(op, path, fd);
	}
	if (!strcmp(op, "create")) {
		fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
		if (fd >= 0) close(fd);
		return done(op, path, fd);
	}
	if (!strcmp(op, "trunc")) return done(op, path, truncate(path, 0));
	if (!strcmp(op, "unlink")) return done(op, path, unlink(path));
	if (!strcmp(op, "mkdir")) return done(op, path, mkdir(path, 0700));
	if (!strcmp(op, "rmdir")) return done(op, path, rmdir(path));
	if (!strcmp(op, "exec")) {
		char *av[2];
		av[0] = (char *)path;
		av[1] = NULL;
		execv(path, av);
		return done(op, path, -1);
	}
	if (!strcmp(op, "escape")) return escape(path);

	fprintf(stderr, "%s: unknown op: %s\n", argv[0], op);
	return 2;
}
