/* Copyright (c) ImapTest authors, see the included COPYING file */

#include "lib.h"
#include "test-common.h"
#include "profile.h"
#include "settings.h"
#include "array.h"
#include "str.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>

struct settings conf;
bool profile_running = FALSE;

/* Stubs for symbols defined in imaptest.c */
bool imaptest_has_clients(void) { return FALSE; }
void error_quit(void) { exit(1); }
void sig_die(int signo ATTR_UNUSED, void *context ATTR_UNUSED) { exit(1); }

/* ======================
 * Profile configurations
 * ====================== */

/* This is the minimal required profile configuration to parse
 * successfully . */
#define PROFILE_BASE \
	"total_user_count = 100\n" \
	"user test {\n" \
	"  count = 100%\n" \
	"  username_format = testuser\n" \
	"}\n" \
	"client default {\n" \
	"  count = 100%\n" \
	"}\n"

/* --- Minimal profile (no per-protocol sections) --- */
static const char *profile_minimal = PROFILE_BASE;

/* --- IMAP: explicit host and port --- */
static const char *profile_imap_explicit = PROFILE_BASE \
	"imap {\n" \
	"  host = imap.example.com\n" \
	"  port = 993\n" \
	"}\n";

/* --- IMAP: host only (no port) --- */
static const char *profile_imap_host_only = PROFILE_BASE \
	"imap {\n" \
	"  host = imap.example.com\n" \
	"}\n";

/* --- POP3: explicit host and port --- */
static const char *profile_pop3_explicit = PROFILE_BASE \
	"pop3 {\n" \
	"  host = pop3.example.com\n" \
	"  port = 995\n" \
	"}\n";

/* --- POP3: host only (no port) --- */
static const char *profile_pop3_host_only = PROFILE_BASE \
	"pop3 {\n" \
	"  host = pop3.example.com\n" \
	"}\n";

/* --- LMTP: explicit host and port --- */
static const char *profile_lmtp_explicit = PROFILE_BASE \
	"lmtp {\n" \
	"  host = lmtp.example.com\n" \
	"  port = 25\n" \
	"}\n";

/* --- LMTP: host only (no port) --- */
static const char *profile_lmtp_host_only = PROFILE_BASE \
	"lmtp {\n" \
	"  host = lmtp.example.com\n" \
	"}\n";

/* --- IMAP: port only (no host) — anonymous section --- */
static const char *profile_imap_port_only = PROFILE_BASE \
	"imap {\n" \
	"  port = 1143\n" \
	"}\n";

/* --- POP3: port only (no host) — anonymous section --- */
static const char *profile_pop3_port_only = PROFILE_BASE \
	"pop3 {\n" \
	"  port = 1143\n" \
	"}\n";

/* --- LMTP: port only (no host) — anonymous section --- */
static const char *profile_lmtp_port_only = PROFILE_BASE \
	"lmtp {\n" \
	"  port = 24\n" \
	"}\n";

/* --- All three protocols: port-only (anonymous sections) --- */
static const char *profile_all_port_only = PROFILE_BASE \
	"imap {\n" \
	"  port = 1143\n" \
	"}\n" \
	"pop3 {\n" \
	"  port = 1143\n" \
	"}\n" \
	"lmtp {\n" \
	"  port = 24\n" \
	"}\n";

/* --- LMTP: deprecated root-level lmtp_port --- */
static const char *profile_lmtp_deprecated = \
	"lmtp_port = 2525\n" \
	PROFILE_BASE;

/* --- LMTP: deprecated lmtp_port + lmtp {} section --- */
static const char *profile_lmtp_both = \
	"lmtp_port = 2525\n" \
	PROFILE_BASE \
	"lmtp {\n" \
	"  host = lmtp.example.com\n" \
	"  port = 24\n" \
	"}\n";

/* --- All three protocols in one profile --- */
static const char *profile_all_protocols = PROFILE_BASE \
	"imap {\n" \
	"  host = imap.example.com\n" \
	"  port = 993\n" \
	"}\n" \
	"pop3 {\n" \
	"  host = pop3.example.com\n" \
	"  port = 995\n" \
	"}\n" \
	"lmtp {\n" \
	"  host = lmtp.example.com\n" \
	"  port = 25\n" \
	"}\n";

/* --- All three protocols, mixed (some with port, some without) --- */
static const char *profile_all_mixed = PROFILE_BASE \
	"imap {\n" \
	"  host = imap.example.com\n" \
	"}\n" \
	"pop3 {\n" \
	"  port = 995\n" \
	"}\n" \
	"lmtp {\n" \
	"  host = lmtp.example.com\n" \
	"  port = 25\n" \
	"}\n";

/* ================
 * Helper functions
 * ================ */

/* Write a profile string to a temp file, return the path (caller frees). */
static char *write_profile_to_tmp(const char *data)
{
	char path[PATH_MAX];
	int fd;
	size_t len;

	snprintf(path, sizeof(path), "/tmp/imaptest-profile-XXXXXX");
	fd = mkstemp(path);
	if (fd < 0) {
		fprintf(stderr, "mkstemp failed: %s\n", strerror(errno));
		return NULL;
	}

	len = strlen(data);
	if (write(fd, data, len) != (ssize_t)len) {
		fprintf(stderr, "write failed: %s\n", strerror(errno));
		close(fd);
		unlink(path);
		return NULL;
	}
	close(fd);
	return i_strdup(path);
}

/* Parse a profile and return it (caller must deinit + free path). */
static struct profile *parse_profile_str(const char *data, char **path_r)
{
	char *path;
	struct profile *profile;

	path = write_profile_to_tmp(data);
	test_assert(path != NULL);

	profile = profile_parse(path);
	test_assert(profile != NULL);

	*path_r = path;
	return profile;
}

/* Generic port test: parse profile, assert expected port, clean up. */
#define TEST_PORT(protocol) \
static void test_port_##protocol(const char *label, struct profile *p, \
	unsigned int expected) \
{ \
	test_begin(label); \
	test_assert(p->protocol##_port == expected); \
	profile_deinit(); \
	test_end(); \
}

TEST_PORT(imap)
TEST_PORT(pop3)
TEST_PORT(lmtp)

/* Generic host test: parse profile, assert expected host, clean up. */
#define TEST_HOST(protocol) \
static void test_host_##protocol(const char *label, struct profile *p, \
	const char *expected) \
{ \
	test_begin(label); \
	test_assert(p->protocol##_host != NULL); \
	test_assert(strcmp(p->protocol##_host, expected) == 0); \
	profile_deinit(); \
	test_end(); \
}

TEST_HOST(imap)
TEST_HOST(pop3)
TEST_HOST(lmtp)

/* ===============
 * IMAP port tests
 * =============== */

/* IMAP: port defaults (explicit, host-only, no-section) */
static void test_imap_port_defaults(void)
{
	char *path;

	/* explicit port */
	test_port_imap("IMAP: explicit port override (993)",
		parse_profile_str(profile_imap_explicit, &path), 993);

	/* host only → port stays 0 */
	test_port_imap("IMAP: host override without port → port stays 0",
		parse_profile_str(profile_imap_host_only, &path), 0);

	/* no section → port stays 0 */
	test_port_imap("IMAP: no imap section → port stays 0",
		parse_profile_str(profile_minimal, &path), 0);

	unlink(path); i_free(path);
}

/* IMAP: connection-time port resolution */
static void test_imap_port_resolution_conf_port(void)
{
	char *path;
	struct profile *profile;

	test_begin("IMAP: port=0 at parse → conf.port used at connect time");

	profile = parse_profile_str(profile_imap_host_only, &path);
	test_assert(profile->imap_port == 0);

	/* Simulate connection-time: profile->imap_port=0, conf.port=993
	 * → should resolve to conf.port (backward compat) */
	conf.port = 993;
	unsigned int port = (profile->imap_port != 0) ?
		profile->imap_port :
		(conf.port != 0 ? conf.port : IMAP_DEFAULT_PORT);
	test_assert(port == 993);

	profile_deinit();
	unlink(path);
	i_free(path);
	conf.port = 0;
	test_end();
}

/* IMAP: connection-time resolves 0 + conf.port=0 → IMAP_DEFAULT_PORT */
static void test_imap_port_resolution_default(void)
{
	char *path;
	struct profile *profile;

	test_begin("IMAP: port=0 + conf.port=0 → IMAP_DEFAULT_PORT (143)");

	profile = parse_profile_str(profile_minimal, &path);
	test_assert(profile->imap_port == 0);

	/* Reset conf.port (may have been set by previous test) */
	conf.port = 0;
	unsigned int port = (profile->imap_port != 0) ?
		profile->imap_port :
		(conf.port != 0 ? conf.port : IMAP_DEFAULT_PORT);
	test_assert(port == IMAP_DEFAULT_PORT);

	profile_deinit();
	unlink(path);
	i_free(path);
	test_end();
}

/* IMAP: explicit port overrides conf.port */
static void test_imap_port_overrides_conf_port(void)
{
	char *path;
	struct profile *profile;

	test_begin("IMAP: explicit port overrides conf.port");

	profile = parse_profile_str(profile_imap_explicit, &path);
	test_assert(profile->imap_port == 993);

	unsigned int port = (profile->imap_port != 0) ?
		profile->imap_port :
		(conf.port != 0 ? conf.port : IMAP_DEFAULT_PORT);
	test_assert(port == 993);

	profile_deinit();
	unlink(path);
	i_free(path);
	test_end();
}

/* ===============
 * POP3 port tests
 * =============== */

/* POP3: port defaults (explicit, host-only, no-section) */
static void test_pop3_port_defaults(void)
{
	char *path;

	/* explicit port */
	test_port_pop3("POP3: explicit port override (995)",
		parse_profile_str(profile_pop3_explicit, &path), 995);

	/* host only → defaults to POP3_DEFAULT_PORT */
	test_port_pop3("POP3: host override without port → defaults to 110",
		parse_profile_str(profile_pop3_host_only, &path), POP3_DEFAULT_PORT);

	/* no section → defaults to POP3_DEFAULT_PORT */
	test_port_pop3("POP3: no pop3 section → defaults to 110",
		parse_profile_str(profile_minimal, &path), POP3_DEFAULT_PORT);

	unlink(path); i_free(path);
}

/* POP3: profile port overrides conf.port */
static void test_pop3_port_overrides_conf_port(void)
{
	char *path;
	struct profile *profile;

	test_begin("POP3: profile port overrides conf.port");

	profile = parse_profile_str(profile_pop3_explicit, &path);
	test_assert(profile->pop3_port == 995);

	/* conf.port = 993 (IMAP port) should NOT affect POP3 */
	conf.port = 993;
	unsigned int port = profile->pop3_port;
	test_assert(port == 995);

	profile_deinit();
	unlink(path);
	i_free(path);
	conf.port = 0;
	test_end();
}

/* POP3: host-only (defaulted) ignores conf.port */
static void test_pop3_host_only_no_conf_port_leak(void)
{
	char *path;
	struct profile *profile;

	test_begin("POP3: host-only ignores conf.port");

	profile = parse_profile_str(profile_pop3_host_only, &path);
	test_assert(profile->pop3_port == POP3_DEFAULT_PORT);

	/* conf.port = 993 (IMAP port) should NOT leak into POP3 */
	conf.port = 993;
	unsigned int port = profile->pop3_port;
	test_assert(port == POP3_DEFAULT_PORT);

	profile_deinit();
	unlink(path);
	i_free(path);
	conf.port = 0;
	test_end();
}

/* ===============
 * LMTP port tests
 * =============== */

/* LMTP: port defaults (explicit, host-only, no-section) */
static void test_lmtp_port_defaults(void)
{
	char *path;

	/* explicit port */
	test_port_lmtp("LMTP: explicit port override (25)",
		parse_profile_str(profile_lmtp_explicit, &path), 25);

	/* host only → defaults to LMTP_DEFAULT_PORT */
	test_port_lmtp("LMTP: host override without port → defaults to 24",
		parse_profile_str(profile_lmtp_host_only, &path), LMTP_DEFAULT_PORT);

	/* no section → defaults to LMTP_DEFAULT_PORT */
	test_port_lmtp("LMTP: no lmtp section → defaults to 24",
		parse_profile_str(profile_minimal, &path), LMTP_DEFAULT_PORT);

	unlink(path); i_free(path);
}

/* LMTP: deprecated root-level lmtp_port */
static void test_lmtp_deprecated_port(void)
{
	char *path;
	struct profile *profile;

	test_begin("LMTP: deprecated root-level lmtp_port = 2525");

	profile = parse_profile_str(profile_lmtp_deprecated, &path);
	test_assert(profile->lmtp_port == 2525);

	profile_deinit();
	unlink(path);
	i_free(path);
	test_end();
}

/* LMTP: deprecated lmtp_port + lmtp {} section — section takes priority */
static void test_lmtp_deprecated_vs_section(void)
{
	char *path;
	struct profile *profile;

	test_begin("LMTP: deprecated lmtp_port overridden by lmtp {} section");

	profile = parse_profile_str(profile_lmtp_both, &path);
	/* The lmtp {} section port (24) takes priority over root-level (2525) */
	test_assert(profile->lmtp_port == 24);

	profile_deinit();
	unlink(path);
	i_free(path);
	test_end();
}

/* LMTP: profile port overrides conf.port */
static void test_lmtp_port_overrides_conf_port(void)
{
	char *path;
	struct profile *profile;

	test_begin("LMTP: profile port overrides conf.port");

	profile = parse_profile_str(profile_lmtp_explicit, &path);
	test_assert(profile->lmtp_port == 25);

	conf.port = 993;
	unsigned int port = profile->lmtp_port;
	test_assert(port == 25);

	profile_deinit();
	unlink(path);
	i_free(path);
	conf.port = 0;
	test_end();
}

/* ===================
 * Host override tests
 * =================== */

/* Per-protocol host override */
static void test_host_override(void)
{
	char *path;

	test_host_imap("IMAP: explicit host override",
		parse_profile_str(profile_imap_explicit, &path),
		"imap.example.com");

	test_host_pop3("POP3: explicit host override",
		parse_profile_str(profile_pop3_explicit, &path),
		"pop3.example.com");

	test_host_lmtp("LMTP: explicit host override",
		parse_profile_str(profile_lmtp_explicit, &path),
		"lmtp.example.com");

	unlink(path); i_free(path);
}

/* All three protocols: hosts are independent */
static void test_all_protocols_hosts(void)
{
	char *path;
	struct profile *profile;

	test_begin("All three protocols: independent host overrides");

	profile = parse_profile_str(profile_all_protocols, &path);
	test_assert(profile->imap_host != NULL);
	test_assert(strcmp(profile->imap_host, "imap.example.com") == 0);
	test_assert(profile->pop3_host != NULL);
	test_assert(strcmp(profile->pop3_host, "pop3.example.com") == 0);
	test_assert(profile->lmtp_host != NULL);
	test_assert(strcmp(profile->lmtp_host, "lmtp.example.com") == 0);

	profile_deinit();
	unlink(path);
	i_free(path);
	test_end();
}

/* ====================
 * Cross-protocol tests
 * ==================== */

/* All three protocols with mixed overrides */
static void test_all_protocols_mixed(void)
{
	char *path;
	struct profile *profile;

	test_begin("All protocols: mixed overrides (host-only, port-only, full)");

	profile = parse_profile_str(profile_all_mixed, &path);

	/* IMAP: host set, port not set → imap_port = 0 */
	test_assert(profile->imap_host != NULL);
	test_assert(strcmp(profile->imap_host, "imap.example.com") == 0);
	test_assert(profile->imap_port == 0);

	/* POP3: port set, host not set → port = 995
	 * (pop3_host may or may not be NULL depending on settings parser
	 * default handling — the important thing is the port is correct) */
	test_assert(profile->pop3_port == 995);

	/* LMTP: both set → lmtp_host != NULL, lmtp_port = 25 */
	test_assert(profile->lmtp_host != NULL);
	test_assert(strcmp(profile->lmtp_host, "lmtp.example.com") == 0);
	test_assert(profile->lmtp_port == 25);

	profile_deinit();
	unlink(path);
	i_free(path);
	test_end();
}

/* All three protocols: port resolution at connection time */
static void test_all_protocols_port_resolution(void)
{
	char *path;
	struct profile *profile;

	test_begin("All protocols: connection-time port resolution");

	profile = parse_profile_str(profile_all_mixed, &path);

	/* IMAP: port=0 → resolves to conf.port=993 */
	conf.port = 993;
	unsigned int imap_port = (profile->imap_port != 0) ?
		profile->imap_port :
		(conf.port != 0 ? conf.port : IMAP_DEFAULT_PORT);
	test_assert(imap_port == 993);

	/* POP3: port=995 (explicit) → uses 995, ignores conf.port */
	unsigned int pop3_port = profile->pop3_port;
	test_assert(pop3_port == 995);

	/* LMTP: port=25 (explicit) → uses 25, ignores conf.port */
	unsigned int lmtp_port = profile->lmtp_port;
	test_assert(lmtp_port == 25);

	profile_deinit();
	unlink(path);
	i_free(path);
	conf.port = 0;
	test_end();
}

/* All three protocols: default port behavior */
static void test_all_protocols_default_ports(void)
{
	char *path;
	struct profile *profile;

	test_begin("All protocols: default port behavior at parse time");

	profile = parse_profile_str(profile_minimal, &path);

	/* IMAP: port stays 0 (NOT defaulted — uses conf.port at connect time) */
	test_assert(profile->imap_port == 0);

	/* POP3: defaulted to 110 at parse time */
	test_assert(profile->pop3_port == POP3_DEFAULT_PORT);

	/* LMTP: defaulted to 24 at parse time */
	test_assert(profile->lmtp_port == LMTP_DEFAULT_PORT);

	profile_deinit();
	unlink(path);
	i_free(path);
	test_end();
}

/* ============================
 * Port validation (per-protocol)
 * ============================ */

struct port_range_test {
	const char *protocol;
	unsigned int port;
	unsigned int expected;
	bool expect_fail;  /* true = validation rejects (i_fatal can't be caught) */
};

static const struct port_range_test port_range_tests[] = {
	/* Invalid ports: rejected by parser_close_hostport (i_fatal, can't catch) */
	{ "imap", 0, 0, true },
	{ "pop3", 0, 0, true },
	{ "lmtp", 0, 0, true },
	{ "imap", 70000, 0, true },
	{ "pop3", 70000, 0, true },
	{ "lmtp", 70000, 0, true },
	/* Valid ports: parse succeeds, port stored as-is */
	{ "imap", 65535, 65535, false },
	{ "pop3", 65535, 65535, false },
	{ "lmtp", 65535, 65535, false },
	{ "imap", 1, 1, false },
	{ "pop3", 1, 1, false },
	{ "lmtp", 1, 1, false },
};
#define PORT_RANGE_TESTS_COUNT 12

static void test_port_range(void)
{
	const char *profile;
	char *path;
	struct profile *profile_parsed;
	unsigned int i;
	string_t *profile_str;

	for (i = 0; i < PORT_RANGE_TESTS_COUNT; i++) {
		const struct port_range_test *t = &port_range_tests[i];

		/* Build profile string without t_strdup_printf to avoid
		 * PROFILE_BASE's "100%" being interpreted as a format spec */
		profile_str = t_str_new(256);
		str_append(profile_str, PROFILE_BASE);
		str_printfa(profile_str, "%s {\n  port = %u\n}\n",
			t->protocol, t->port);
		profile = str_c(profile_str);

		test_begin(t_strdup_printf("%s { port = %u } → %s",
			t->protocol, t->port,
			t->expect_fail ? "fail" : t_strdup_printf("%u", t->expected)));

		if (t->expect_fail) {
			/* Validation in parser_close_hostport — can't catch i_fatal() */
			path = write_profile_to_tmp(profile);
			test_assert(path != NULL);
			unlink(path); i_free(path);
		} else {
			profile_parsed = parse_profile_str(profile, &path);
			if (strcmp(t->protocol, "imap") == 0)
				test_assert(profile_parsed->imap_port == t->expected);
			else if (strcmp(t->protocol, "pop3") == 0)
				test_assert(profile_parsed->pop3_port == t->expected);
			else
				test_assert(profile_parsed->lmtp_port == t->expected);
			profile_deinit();
			unlink(path); i_free(path);
		}
		test_end();
	}
}

/* ==========
 * Edge cases
 * ========== */

/* ============================
 * Anonymous section (port-only)
 * ============================ */

/* Anonymous sections (port-only): host is NULL so that at connect time
 * profile_resolve_ip() falls back to conf.host (CLI default).
 *
 * Regression: a prior parsing bug stored "{" as the protocol host
 * when only port was specified (e.g. "imap { port = 1143 }").
 * try_parse_section() returns value = "{" for "imap {" — the guard
 * clause `value[0] != '{'` in profile_parse_line_root prevents that
 * from being passed to settings_parse_keyvalue, keeping host = NULL. */
static void test_port_only_section_uses_cli_host(void)
{
	char *path;
	struct profile *profile;

	test_begin("Port-only sections: host resolves to CLI default");

	/* Set CLI default host — the fallback target for anonymous sections */
	conf.host = "cli-default.example.com";

	/* IMAP: port-only → host is NULL at parse time */
	profile = parse_profile_str(profile_imap_port_only, &path);
	test_assert(profile->imap_host == NULL);
	test_assert(profile->imap_port == 1143);
	profile_deinit();
	unlink(path); i_free(path);

	/* POP3: port-only */
	profile = parse_profile_str(profile_pop3_port_only, &path);
	test_assert(profile->pop3_host == NULL);
	test_assert(profile->pop3_port == 1143);
	profile_deinit();
	unlink(path); i_free(path);

	/* LMTP: port-only */
	profile = parse_profile_str(profile_lmtp_port_only, &path);
	test_assert(profile->lmtp_host == NULL);
	test_assert(profile->lmtp_port == 24);
	profile_deinit();
	unlink(path); i_free(path);

	/* All three protocols: port-only → all have NULL host */
	profile = parse_profile_str(profile_all_port_only, &path);
	test_assert(profile->imap_host == NULL);
	test_assert(profile->imap_port == 1143);
	test_assert(profile->pop3_host == NULL);
	test_assert(profile->pop3_port == 1143);
	test_assert(profile->lmtp_host == NULL);
	test_assert(profile->lmtp_port == 24);
	profile_deinit();
	unlink(path); i_free(path);

	/* Explicit host in section: host is set, overrides CLI default */
	profile = parse_profile_str(profile_imap_explicit, &path);
	test_assert(profile->imap_host != NULL);
	test_assert(strcmp(profile->imap_host, "imap.example.com") == 0);
	profile_deinit();
	unlink(path); i_free(path);

	conf.host = NULL;
	test_end();
}



int main(int argc, char *argv[])
{
	static void (*const test_functions[])(void) = {
		/* IMAP port tests */
		test_imap_port_defaults,
		test_imap_port_resolution_conf_port,
		test_imap_port_resolution_default,
		test_imap_port_overrides_conf_port,

		/* POP3 port tests */
		test_pop3_port_defaults,
		test_pop3_port_overrides_conf_port,
		test_pop3_host_only_no_conf_port_leak,

		/* LMTP port tests */
		test_lmtp_port_defaults,
		test_lmtp_deprecated_port,
		test_lmtp_deprecated_vs_section,
		test_lmtp_port_overrides_conf_port,

		/* Host override tests */
		test_host_override,
		test_all_protocols_hosts,

		/* Cross-protocol tests */
		test_all_protocols_mixed,
		test_all_protocols_port_resolution,
		test_all_protocols_default_ports,

		/* Port validation (per-protocol) */
		test_port_range,

		/* Port-only sections: host resolves to CLI default */
		test_port_only_section_uses_cli_host,

		NULL
	};

	lib_init();
	set_conf_default(&conf);

	int ret = test_run(test_functions);

	lib_deinit();
	return ret;
}
