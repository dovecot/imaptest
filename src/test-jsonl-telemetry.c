/* Copyright (c) ImapTest authors, see the included COPYING file */

/*
 * Unit tests for the JSON Lines telemetry subsystem.
 *
 * Tests the event generation API and JSONL exporter end-to-end by:
 *  1. Initializing the exporter to a temporary file
 *  2. Firing each event type
 *  3. Reading the file and validating JSON structure/fields
 *  4. Testing lifecycle (init/deinit, no-op when not initialized)
 *
 * Does NOT require a running IMAP/POP3 server.
 */

#include "lib.h"
#include "str.h"
#include "ostream.h"
#include "json-generator.h"
#include "imaptest-events.h"
#include "imaptest-exporter.h"
#include "imaptest-exporter-jsonl.h"
#include "client-state.h"
#include "settings.h"
#include "test-common.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

struct settings conf;
bool profile_running = FALSE;

/*
 * Stubs for symbols defined in imaptest.c (not linked for unit tests).
 */
bool imaptest_has_clients(void) { return FALSE; }
void sig_die(int signo ATTR_UNUSED, void *context ATTR_UNUSED) { exit(1); }
void error_quit(void) { exit(1); }

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

/* Create a temp file, return its path (i_strdup'd). Caller must unlink. */
static char *test_create_temp_file(void)
{
	char *path = i_strdup("/tmp/imaptest-jsonl-test-XXXXXX");
	int fd = mkstemp(path);
	if (fd == -1)
		i_fatal("mkstemp failed");
	close(fd);
	return path;
}

/* Read entire file into a string. Returns NULL on failure. */
static char *test_read_file(const char *path)
{
	FILE *f = fopen(path, "r");
	if (f == NULL)
		return NULL;

	struct stat st;
	if (fstat(fileno(f), &st) < 0) {
		fclose(f);
		return NULL;
	}

	char *buf = i_malloc(st.st_size + 1);
	size_t n = fread(buf, 1, st.st_size, f);
	buf[n] = '\0';
	fclose(f);
	return buf;
}

/*
 * Simple JSON field validator: checks that a JSON string contains
 * a given key with a string value matching expected.
 * Returns TRUE if found, FALSE otherwise.
 * This is a lightweight check — not a full JSON parser.
 */
static bool test_json_has_string_field(const char *json,
					const char *key, const char *expected)
{
	const char *pattern = t_strdup_printf("\"%s\":\"%s\"", key, expected);
	return strstr(json, pattern) != NULL;
}

/* Check that a JSON string contains a numeric key:value pair. */
static bool test_json_has_number_field(const char *json,
					const char *key, unsigned long long value)
{
	const char *pattern = t_strdup_printf("\"%s\":%llu", key, value);
	return strstr(json, pattern) != NULL;
}

/* Check that a JSON string contains a boolean key:value pair. */
static bool test_json_has_bool_field(const char *json,
				     const char *key, bool value)
{
	const char *pattern = t_strdup_printf("\"%s\":%s", key, value ? "true" : "false");
	return strstr(json, pattern) != NULL;
}

/* Check that a JSON string contains a key (any value type). */
static bool test_json_has_key(const char *json, const char *key)
{
	const char *pattern = t_strdup_printf("\"%s\":", key);
	return strstr(json, pattern) != NULL;
}

/* ------------------------------------------------------------------ */
/* Tests                                                               */
/* ------------------------------------------------------------------ */

static void test_exporter_init_deinit(void)
{
	char *path = test_create_temp_file();

	test_begin("exporter init/deinit lifecycle");

	test_assert(!imaptest_exporter_is_initialized());

	test_assert(imaptest_exporter_init(t_strdup_printf("jsonl:path=%s", path)) == 0);
	test_assert(imaptest_exporter_is_initialized());

	imaptest_exporter_deinit();
	test_assert(!imaptest_exporter_is_initialized());

	unlink(path);
	i_free(path);

	test_end();
}

static void test_exporter_init_bad_path(void)
{
	test_begin("exporter init with bad path");

	test_assert(!imaptest_exporter_is_initialized());

	/* Driver is already registered from main(). Init with bad path
	 * should fail and leave the driver un-initialized. The i_error()
	 * inside imaptest_exporter_init() is expected. */
	test_expect_errors(1);
	test_assert(imaptest_exporter_init("jsonl:path=/nonexistent/dir/file.jsonl") == -1);
	test_assert(!imaptest_exporter_is_initialized());

	test_end();
}

static void test_events_noop_when_not_initialized(void)
{
	struct imaptest_event ev;

	test_begin("events are no-ops when exporter not initialized");

	test_assert(!imaptest_exporter_is_initialized());

	/* These should not crash — they check is_initialized() and return early */
	imaptest_event_cmd_completed(&ev, 1, "user", "IMAP", "SELECT", "OK",
				     1000, "INBOX", 42);
	imaptest_event_client_connected(&ev, 1, "user", "IMAP", 143);
	imaptest_event_client_disconnected(&ev, 1, "user", "Closed", 5000);
	imaptest_event_interval_stats(&ev, 5, 10, 0, 0, 0, NULL, NULL, NULL);
	imaptest_event_test_result(&ev, "test1", TRUE, FALSE, "");
	imaptest_event_test_summary(&ev, 1, 0, 0, 0, 0, 0, 0);
	imaptest_event_stall_detected(&ev, 1, "user", 30, "SELECT");
	imaptest_event_checkpoint_error(&ev, 1, "user", "INBOX", "test error");

	test_assert(!imaptest_exporter_is_initialized());

	test_end();
}

static void test_event_cmd_completed(void)
{
	char *path = test_create_temp_file();
	struct imaptest_event ev;

	test_begin("cmd_completed event serialization");

	test_assert(imaptest_exporter_init(t_strdup_printf("jsonl:path=%s", path)) == 0);

	imaptest_event_cmd_completed(&ev, 7, "testuser", "IMAP", "SELECT",
				     "OK", 12345, "INBOX", 99);

	imaptest_exporter_deinit();

	char *content = test_read_file(path);
	test_assert(content != NULL);

	/* Check all fields */
	test_assert(test_json_has_string_field(content, "event", "cmd_completed"));
	test_assert(test_json_has_string_field(content, "username", "testuser"));
	test_assert(test_json_has_string_field(content, "protocol", "IMAP"));
	test_assert(test_json_has_string_field(content, "state", "SELECT"));
	test_assert(test_json_has_string_field(content, "reply", "OK"));
	test_assert(test_json_has_string_field(content, "mailbox", "INBOX"));
	test_assert(test_json_has_number_field(content, "client_id", 7));
	test_assert(test_json_has_number_field(content, "duration_usecs", 12345));
	test_assert(test_json_has_number_field(content, "tag", 99));
	test_assert(test_json_has_key(content, "ts"));

	i_free(content);
	unlink(path);
	i_free(path);

	test_end();
}

static void test_event_client_connected(void)
{
	char *path = test_create_temp_file();
	struct imaptest_event ev;

	test_begin("client_connected event serialization");

	test_assert(imaptest_exporter_init(t_strdup_printf("jsonl:path=%s", path)) == 0);

	imaptest_event_client_connected(&ev, 3, "admin", "POP3", 110);

	imaptest_exporter_deinit();

	char *content = test_read_file(path);
	test_assert(content != NULL);

	test_assert(test_json_has_string_field(content, "event", "client_connected"));
	test_assert(test_json_has_string_field(content, "username", "admin"));
	test_assert(test_json_has_string_field(content, "protocol", "POP3"));
	test_assert(test_json_has_number_field(content, "client_id", 3));
	test_assert(test_json_has_number_field(content, "port", 110));

	i_free(content);
	unlink(path);
	i_free(path);

	test_end();
}

static void test_event_client_disconnected(void)
{
	char *path = test_create_temp_file();
	struct imaptest_event ev;

	test_begin("client_disconnected event serialization");

	test_assert(imaptest_exporter_init(t_strdup_printf("jsonl:path=%s", path)) == 0);

	imaptest_event_client_disconnected(&ev, 3, "admin", "Logout", 987654);

	imaptest_exporter_deinit();

	char *content = test_read_file(path);
	test_assert(content != NULL);

	test_assert(test_json_has_string_field(content, "event", "client_disconnected"));
	test_assert(test_json_has_string_field(content, "username", "admin"));
	test_assert(test_json_has_string_field(content, "reason", "Logout"));
	test_assert(test_json_has_number_field(content, "client_id", 3));
	test_assert(test_json_has_number_field(content, "duration_usecs", 987654));

	i_free(content);
	unlink(path);
	i_free(path);

	test_end();
}

static void test_event_test_result(void)
{
	char *path = test_create_temp_file();
	struct imaptest_event ev;

	test_begin("test_result event serialization");

	test_assert(imaptest_exporter_init(t_strdup_printf("jsonl:path=%s", path)) == 0);

	/* Passed test */
	imaptest_event_test_result(&ev, "FETCH-basic", TRUE, FALSE, "");

	imaptest_exporter_deinit();

	char *content = test_read_file(path);
	test_assert(content != NULL);

	test_assert(test_json_has_string_field(content, "event", "test_result"));
	test_assert(test_json_has_string_field(content, "test_name", "FETCH-basic"));
	test_assert(test_json_has_bool_field(content, "passed", TRUE));
	test_assert(test_json_has_bool_field(content, "skipped", FALSE));

	i_free(content);

	/* Failed test */
	test_assert(imaptest_exporter_init(t_strdup_printf("jsonl:path=%s", path)) == 0);

	imaptest_event_test_result(&ev, "SEARCH-headers", FALSE, FALSE,
				   "Unexpected reply: NO");

	imaptest_exporter_deinit();

	content = test_read_file(path);
	test_assert(content != NULL);

	test_assert(test_json_has_string_field(content, "test_name", "SEARCH-headers"));
	test_assert(test_json_has_bool_field(content, "passed", FALSE));
	test_assert(test_json_has_string_field(content, "failure_reason",
					      "Unexpected reply: NO"));

	i_free(content);

	/* Skipped test */
	test_assert(imaptest_exporter_init(t_strdup_printf("jsonl:path=%s", path)) == 0);

	imaptest_event_test_result(&ev, "SORT-test", TRUE, TRUE, "");

	imaptest_exporter_deinit();

	content = test_read_file(path);
	test_assert(content != NULL);

	test_assert(test_json_has_bool_field(content, "skipped", TRUE));

	i_free(content);
	unlink(path);
	i_free(path);

	test_end();
}

static void test_event_test_summary(void)
{
	char *path = test_create_temp_file();
	struct imaptest_event ev;

	test_begin("test_summary event serialization");

	test_assert(imaptest_exporter_init(t_strdup_printf("jsonl:path=%s", path)) == 0);

	imaptest_event_test_summary(&ev, 5, 1, 0, 2, 20, 0, 3);

	imaptest_exporter_deinit();

	char *content = test_read_file(path);
	test_assert(content != NULL);

	test_assert(test_json_has_string_field(content, "event", "test_summary"));
	test_assert(test_json_has_number_field(content, "total_groups", 5));
	test_assert(test_json_has_number_field(content, "group_failures", 1));
	test_assert(test_json_has_number_field(content, "group_skips", 0));
	test_assert(test_json_has_number_field(content, "base_failures", 2));
	test_assert(test_json_has_number_field(content, "base_tests", 20));
	test_assert(test_json_has_number_field(content, "ext_failures", 0));
	test_assert(test_json_has_number_field(content, "ext_tests", 3));

	i_free(content);
	unlink(path);
	i_free(path);

	test_end();
}

static void test_event_stall_detected(void)
{
	char *path = test_create_temp_file();
	struct imaptest_event ev;

	test_begin("client_stalled event serialization");

	test_assert(imaptest_exporter_init(t_strdup_printf("jsonl:path=%s", path)) == 0);

	imaptest_event_stall_detected(&ev, 4, "stalled_user", 45, "IDLE");

	imaptest_exporter_deinit();

	char *content = test_read_file(path);
	test_assert(content != NULL);

	test_assert(test_json_has_string_field(content, "event", "client_stalled"));
	test_assert(test_json_has_string_field(content, "username", "stalled_user"));
	test_assert(test_json_has_string_field(content, "state", "IDLE"));
	test_assert(test_json_has_number_field(content, "client_id", 4));
	test_assert(test_json_has_number_field(content, "stalled_secs", 45));

	i_free(content);
	unlink(path);
	i_free(path);

	test_end();
}

static void test_event_checkpoint_error(void)
{
	char *path = test_create_temp_file();
	struct imaptest_event ev;

	test_begin("checkpoint_error event serialization");

	test_assert(imaptest_exporter_init(t_strdup_printf("jsonl:path=%s", path)) == 0);

	imaptest_event_checkpoint_error(&ev, 2, "cp_user", "INBOX",
					"Checkpoint: Message seq=1 UID 5 != 3");

	imaptest_exporter_deinit();

	char *content = test_read_file(path);
	test_assert(content != NULL);

	test_assert(test_json_has_string_field(content, "event", "checkpoint_error"));
	test_assert(test_json_has_string_field(content, "username", "cp_user"));
	test_assert(test_json_has_string_field(content, "mailbox", "INBOX"));
	test_assert(test_json_has_number_field(content, "client_id", 2));
	test_assert(test_json_has_string_field(content, "detail",
					      "Checkpoint: Message seq=1 UID 5 != 3"));

	i_free(content);
	unlink(path);
	i_free(path);

	test_end();
}

static void test_event_interval_stats(void)
{
	char *path = test_create_temp_file();
	struct imaptest_event ev;

	test_begin("interval_stats event serialization");

	/* Set up minimal state probabilities so at least one state is visible */
	states[1].probability = 100; /* LOGIN */
	states[2].probability = 100; /* SELECT */

	unsigned int counters[STATE_COUNT] = { 0 };
	unsigned long long timers[STATE_COUNT] = { 0 };
	unsigned int timer_counts[STATE_COUNT] = { 0 };

	counters[1] = 10;  /* LOGIN count */
	counters[2] = 8;   /* SELECT count */
	timers[1] = 50000; /* 50ms total for LOGIN */
	timers[2] = 40000; /* 40ms total for SELECT */
	timer_counts[1] = 10;
	timer_counts[2] = 8;

	test_assert(imaptest_exporter_init(t_strdup_printf("jsonl:path=%s", path)) == 0);

	imaptest_event_interval_stats(&ev, 5, 10, 1, 3, 2,
				      counters, timers, timer_counts);

	imaptest_exporter_deinit();

	char *content = test_read_file(path);
	test_assert(content != NULL);

	test_assert(test_json_has_string_field(content, "event", "interval_stats"));
	test_assert(test_json_has_number_field(content, "active_clients", 5));
	test_assert(test_json_has_number_field(content, "total_clients", 10));
	test_assert(test_json_has_number_field(content, "stalled_count", 1));
	test_assert(test_json_has_number_field(content, "total_disconnects", 3));

	/* Check state-specific fields — LOGIN has count=10, avg=50000/10=5000 usecs = 5 msecs */
	test_assert(test_json_has_key(content, "LOGIN_count"));
	test_assert(test_json_has_key(content, "LOGIN_avg_msecs"));
	test_assert(test_json_has_key(content, "SELECT_count"));
	test_assert(test_json_has_key(content, "SELECT_avg_msecs"));

	i_free(content);
	unlink(path);
	i_free(path);

	test_end();
}

static void test_multiple_events_sequential(void)
{
	char *path = test_create_temp_file();
	struct imaptest_event ev;

	test_begin("multiple events produce separate JSONL lines");

	test_assert(imaptest_exporter_init(t_strdup_printf("jsonl:path=%s", path)) == 0);

	imaptest_event_client_connected(&ev, 1, "user1", "IMAP", 143);
	imaptest_event_cmd_completed(&ev, 1, "user1", "IMAP", "SELECT", "OK",
				     5000, "INBOX", 1);
	imaptest_event_client_disconnected(&ev, 1, "user1", "Logout", 100000);

	imaptest_exporter_deinit();

	char *content = test_read_file(path);
	test_assert(content != NULL);

	/* Count newlines — should be exactly 3 (one per event) */
	unsigned int lines = 0;
	for (const char *p = content; *p; p++) {
		if (*p == '\n')
			lines++;
	}
	test_assert(lines == 3);

	/* Each line should have an "event" field */
	unsigned int event_count = 0;
	const char *tmp = content;
	while ((tmp = strstr(tmp, "\"event\":")) != NULL) {
		event_count++;
		tmp++;
	}
	test_assert(event_count == 3);

	i_free(content);
	unlink(path);
	i_free(path);

	test_end();
}

static void test_event_type_enum_count(void)
{
	test_begin("event_type enum has EVENT_TYPE_COUNT sentinel");

	test_assert(EVENT_TYPE_COUNT == 8);
	test_assert(EVENT_TYPE_CMD_COMPLETED == 0);
	test_assert(EVENT_TYPE_CLIENT_CONNECTED == 1);
	test_assert(EVENT_TYPE_CLIENT_DISCONNECTED == 2);
	test_assert(EVENT_TYPE_INTERVAL_STATS == 3);
	test_assert(EVENT_TYPE_TEST_RESULT == 4);
	test_assert(EVENT_TYPE_TEST_SUMMARY == 5);
	test_assert(EVENT_TYPE_CLIENT_STALLED == 6);
	test_assert(EVENT_TYPE_CHECKPOINT_ERROR == 7);

	test_end();
}

/* ------------------------------------------------------------------ */
/* Main                                                                */
/* ------------------------------------------------------------------ */

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_exporter_init_deinit,
		test_exporter_init_bad_path,
		test_events_noop_when_not_initialized,
		test_event_cmd_completed,
		test_event_client_connected,
		test_event_client_disconnected,
		test_event_test_result,
		test_event_test_summary,
		test_event_stall_detected,
		test_event_checkpoint_error,
		test_event_interval_stats,
		test_multiple_events_sequential,
		test_event_type_enum_count,
		NULL
	};

	lib_init();
	set_conf_default(&conf);

	/* Register built-in exporters before running tests */
	imaptest_exporter_jsonl_register();

	int ret = test_run(test_functions);

	lib_deinit();
	return ret;
}
