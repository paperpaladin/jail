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
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
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

/*
 * The grant flags, and exactly which rights each one means. A table rather
 * than a chain of strcmp because the difference between these four is one or
 * two bits, and those bits are the entire feature: seeing them in a column is
 * the only way to review them.
 */
static const struct { const char *flag; uint64_t rights; } grant[] = {
	{ "--ro", JAIL_FS_READ },
	{ "--rw", JAIL_FS_READ | JAIL_FS_WRITE },
	/*
	 * Run it and read it, but do not enumerate it. Landlock gates the
	 * operation rather than the path lookup, so dropping READ_DIR leaves
	 * open() on a filename the process already knows working -- which is
	 * the point: a compromised process can use /usr/bin/cc but cannot take
	 * an inventory of what else is installed.
	 */
	{ "--rox", JAIL_FS_READ & ~LANDLOCK_ACCESS_FS_READ_DIR },
	/*
	 * Write it, but never run what was written. A scratch or download
	 * directory, where the thing you are defending against is the process
	 * fetching a payload and then executing it.
	 */
	{ "--rw-no-exec",
	  (JAIL_FS_READ | JAIL_FS_WRITE) & ~LANDLOCK_ACCESS_FS_EXECUTE },
};
#define NGRANT ((int)(sizeof grant / sizeof *grant))

/* The highest ABI this program knows how to use. */
#define JAIL_ABI_KNOWN 5

static const char *prog = "jail";

static void die(const char *what) {
	fprintf(stderr, "%s: %s: %s\n", prog, what, strerror(errno));
	exit(125); /* 125: jail itself failed, distinct from any child status */
}

static void usage(FILE *f) {
	fprintf(f,
	    "usage: %s [GRANT PATH]... [--strict] -- CMD [ARGS...]\n"
	    "\n"
	    "  --ro PATH          read and execute beneath PATH\n"
	    "  --rw PATH          read, execute, write, create and delete\n"
	    "  --rox PATH         read and execute, but no directory listing\n"
	    "  --rw-no-exec PATH  read, write, create and delete, but no execute\n"
	    "  --deny PATH        withhold PATH from a broader grant above it\n"
	    "  --strict           fail instead of degrading when the kernel's\n"
	    "                     Landlock ABI is older than this build knows\n"
	    "  --abi              print the kernel's Landlock ABI version and exit\n"
	    "\n"
	    "env JAIL_ABI_MAX=N pretends the kernel's ABI is at most N (clamps\n"
	    "down only) so the degradation path can be tested on a new kernel.\n"
	    "\n"
	    "Anything not granted is denied: the kernel returns EACCES. The\n"
	    "restriction is inherited by all descendants and cannot be removed.\n"
	    "CMD must itself live under a granted path, as must its shared\n"
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

/*
 * The parsed rules, grown on demand.
 *
 * This was a fixed array of 64 with a "too many path rules" refusal, which was
 * fine while every rule came from a flag the user typed. It stops being fine
 * the moment one flag can expand into many: --deny has to be implemented by
 * granting siblings, because Landlock has no way to subtract a right, and a
 * single --deny under a directory with a few hundred entries produces a few
 * hundred rules.
 *
 * Doubling from 16. The kernel has no limit on rules per ruleset worth
 * worrying about here; the real ceiling is one open file descriptor per rule
 * at install time, and those are closed as we go.
 */
typedef struct { const char *path; uint64_t rights; } Rule;

static Rule *rules;
static int nrule, rulecap;

static void rule_add(const char *path, uint64_t rights) {
	if (nrule == rulecap) {
		rulecap = rulecap ? rulecap * 2 : 16;
		Rule *p = realloc(rules, (size_t)rulecap * sizeof *p);
		if (!p) {
			fprintf(stderr, "%s: out of memory for %d path rules\n",
			        prog, rulecap);
			exit(125);
		}
		rules = p;
	}
	rules[nrule].path = path;
	rules[nrule].rights = rights;
	nrule++;
}

/*
 * --deny, which Landlock has no way to express.
 *
 * A rule only ever ADDS rights, and that was established against the kernel
 * rather than assumed. Two facts, both measured on ABI 10:
 *
 *   - A rule with allowed_access == 0 is refused with ENOMSG, so "deny" cannot
 *     be written as a rule granting nothing.
 *   - Rules within one ruleset are additive, not shadowed by depth. Granting
 *     READ_FILE on a parent and only READ_DIR on a child leaves files under
 *     the child readable. There is no subtraction at any depth.
 *
 * So the only way to withhold a subtree is to never grant anything that
 * encloses it. Walk down from the grant toward the denied path and grant each
 * level's *other* children individually; the path to the denied subtree is
 * simply never granted.
 *
 * The cost is real and worth naming: the directories between the grant and the
 * denied path end up with no rule of their own, so they cannot be listed. A
 * rule on them would grant listing of everything beneath, the denied subtree
 * included. Traversal through them still works, because Landlock gates
 * operations and not path lookup -- only the `ls` of those particular
 * directories is lost.
 *
 * shortcut: one rule per sibling, and every rule costs an open file descriptor
 * while the ruleset is built. A --deny under a directory of tens of thousands
 * of entries will meet RLIMIT_NOFILE. Upgrade path: install rules in batches,
 * closing each fd as it goes, which add_path already does -- what is missing is
 * not holding the whole expansion in memory first.
 */
static char **deny;
static int ndeny;

static char *xstrdup(const char *s) {
	char *p = strdup(s);
	if (!p) { fprintf(stderr, "%s: out of memory\n", prog); exit(125); }
	return p;
}

/*
 * Canonical, because a security tool that compares paths as strings can be
 * walked around with a symlink or a `..`. realpath(3) resolves both, and the
 * resolved path is also what the kernel will match at open() time.
 */
static char *canon(const char *path, const char *what) {
	char *r = realpath(path, NULL);
	if (!r) {
		fprintf(stderr, "%s: %s %s: %s\n", prog, what, path, strerror(errno));
		exit(125);
	}
	return r;
}

/* Is `d` the same path as `p`, or inside it? Both must be canonical. */
static int inside(const char *p, const char *d) {
	size_t n = strlen(p);
	if (strncmp(p, d, n) != 0) return 0;
	if (d[n] == 0) return 1;
	/* "/ab" is not inside "/a", but "/a/b" is. */
	return p[n - 1] == '/' || d[n] == '/';
}

/*
 * `path` is canonical. Grants it, or splits it and recurses, so that nothing
 * enclosing a denied path is ever granted.
 *
 * Every child is canonicalised before it is looked at, and only children whose
 * canonical path lies STRICTLY INSIDE `path` are considered at all. Three
 * different symlink attacks made that necessary, and the tests for all three
 * failed on the first version of this function, which compared the names as
 * written:
 *
 *   - A sibling symlink pointing into the denied subtree. `--deny d` skips the
 *     entry named `d`, then grants the entry named `alias`, and add_path opens
 *     with O_PATH, which follows -- so the denied inode is granted under
 *     another name and the deny does nothing.
 *   - The same thing in reverse: `--deny alias` canonicalises to `d`, and the
 *     entry literally named `d` is skipped, but `alias` is granted.
 *   - A symlink pointing OUT of the grant. Granting it would hand over its
 *     target, so adding a --deny could make the sandbox *wider* than the same
 *     command without one. That is the worst of the three and the reason the
 *     test is containment rather than just inequality.
 *
 * Strict containment also guarantees termination, which matters because a
 * symlink to its own ancestor would otherwise recurse forever.
 */
static void expand(const char *path, uint64_t rights) {
	int has_denied_child = 0;

	for (int i = 0; i < ndeny; i++) {
		if (!strcmp(deny[i], path)) return;   /* this whole subtree is out */
		if (inside(path, deny[i])) has_denied_child = 1;
	}
	if (!has_denied_child) {
		rule_add(xstrdup(path), rights);
		return;
	}

	DIR *d = opendir(path);
	if (!d) {
		/* Fail closed. Being unable to enumerate a directory we must split
		 * means we cannot tell which children are safe to grant, and
		 * granting the lot would hand over the thing being denied. */
		fprintf(stderr, "%s: cannot read %s to apply --deny: %s\n",
		        prog, path, strerror(errno));
		exit(125);
	}
	struct dirent *e;
	while ((e = readdir(d))) {
		if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
		char child[PATH_MAX];
		int n = snprintf(child, sizeof child, "%s/%s", path, e->d_name);
		if (n < 0 || n >= (int)sizeof child) {
			fprintf(stderr, "%s: path too long under %s: %s\n",
			        prog, path, e->d_name);
			closedir(d);
			exit(125);
		}
		/* A dangling symlink resolves to nothing and grants nothing, which
		 * is an ordinary thing to find in a directory rather than an error. */
		char *real = realpath(child, NULL);
		if (!real) continue;
		if (inside(path, real) && strcmp(path, real) != 0)
			expand(real, rights);
		free(real);
	}
	closedir(d);
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
	int strict = 0, i, g, cmd;
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
		for (g = 0; g < NGRANT && strcmp(argv[i], grant[g].flag); g++)
			;
		if (g < NGRANT) {
			if (i + 1 >= argc) {
				fprintf(stderr, "%s: %s needs a PATH\n", prog,
				    argv[i]);
				return 125;
			}
			rule_add(argv[++i], grant[g].rights);
			continue;
		}
		if (!strcmp(argv[i], "--deny")) {
			if (i + 1 >= argc) {
				fprintf(stderr, "%s: --deny needs a PATH\n", prog);
				return 125;
			}
			char **p = realloc(deny, (size_t)(ndeny + 1) * sizeof *p);
			if (!p) { fprintf(stderr, "%s: out of memory\n", prog); return 125; }
			deny = p;
			/* Canonicalised here so a typo fails now rather than silently
			 * denying nothing, and so a symlink cannot sidestep it. */
			deny[ndeny++] = canon(argv[++i], "--deny");
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

	/*
	 * JAIL_ABI_MAX clamps the detected ABI *downward* only. It exists
	 * because the degradation path is the part of a Landlock program most
	 * likely to be wrong and least likely to be exercised: you cannot test
	 * it on a new kernel without it. Clamping up is refused -- pretending
	 * to have rights the kernel lacks would make create_ruleset EINVAL at
	 * best and silently unenforced at worst, which is the exact failure
	 * mode this whole dance exists to prevent.
	 */
	{
		const char *e = getenv("JAIL_ABI_MAX");
		if (e && *e) {
			int want = atoi(e);
			if (want > 0 && want < abi) abi = want;
		}
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

	/*
	 * Expansion happens here, after the ruleset exists and before anything is
	 * installed. Denies are global rather than positional: --deny applies to
	 * every grant it falls inside, wherever it sits on the command line,
	 * because the alternative is a flag whose meaning depends on argument
	 * order and nobody gets that right from the help text.
	 */
	if (ndeny) {
		Rule *typed = rules;
		int ntyped = nrule;

		/* Validate before expanding. A --deny inside no grant denies
		 * nothing, which is a typo worth refusing rather than a no-op worth
		 * ignoring -- and refusing it before any work is done means the
		 * diagnostic is not buried under a thousand expanded rules. */
		for (int d = 0; d < ndeny; d++) {
			int covered = 0;
			for (i = 0; i < ntyped && !covered; i++) {
				char *root = canon(typed[i].path, "");
				covered = inside(root, deny[d]);
				free(root);
			}
			if (!covered) {
				fprintf(stderr, "%s: --deny %s is not beneath any grant, "
				        "so it denies nothing\n", prog, deny[d]);
				return 125;
			}
		}

		rules = NULL;
		nrule = rulecap = 0;
		for (i = 0; i < ntyped; i++) {
			char *root = canon(typed[i].path, "");
			expand(root, typed[i].rights);
			free(root);
		}
		free(typed);
	}

	for (i = 0; i < nrule; i++)
		add_path(ruleset, rules[i].path, rules[i].rights & mask);

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
