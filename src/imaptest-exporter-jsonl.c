/* Copyright (c) ImapTest authors, see the included COPYING file */

#include "lib.h"
#include "ostream.h"
#include "str.h"
#include "time-util.h"
#include "json-generator.h"
#include "client-state.h"
#include "imaptest-events.h"
#include "imaptest.h"
#include "imaptest-exporter-jsonl.h"
#include "imaptest-exporter.h"
#include <sys/time.h>
#include <fcntl.h>
#include <unistd.h>

#define JSON_GEN_BOOL(ej, name, val) \
	(void)json_generate_object_member((ej)->gen, name); \
	if (val) (void)json_generate_true((ej)->gen); \
	else (void)json_generate_false((ej)->gen);
#define JSON_GEN_NUMBER(ej, name, val) \
	(void)json_generate_object_member((ej)->gen, name); \
	(void)json_generate_number((ej)->gen, val);
#define JSON_GEN_STRING(ej, name, val) \
	(void)json_generate_object_member((ej)->gen, name); \
	(void)json_generate_string((ej)->gen, val);

/*
 * Global JSONL output stream. Safe because imaptest uses a
 * single-threaded ioloop — no concurrent access is possible.
 * Do NOT add threading to this module without introducing locking.
 */
static struct ostream *jsonl_ostream = NULL;

struct jsonl_event {
	struct json_generator *gen;
	string_t *line;
};

static int
jsonl_init(const char *options)
{
	const char *path = NULL;
	int fd;

	i_assert(jsonl_ostream == NULL);

	/* Parse options: "path=/path/to/file" or bare path */
	if (strncmp(options, "path=", 5) == 0)
		path = options + 5;
	else
		path = options;

	if (path == NULL || *path == '\0') {
		i_error("JSONL exporter: output path not specified");
		return -1;
	}

	fd = creat(path, 0600);
	if (fd == -1)
		return -1;
	jsonl_ostream = o_stream_create_fd_file_autoclose(&fd, 0);
	if (jsonl_ostream != NULL)
		return 0;

	close(fd);
	return -1;
}

static void
jsonl_deinit(void)
{
	if (jsonl_ostream != NULL) {
		if (o_stream_flush(jsonl_ostream) < 0)
			i_error("Failed to flush JSONL event output — %zu bytes may be lost: %s",
				o_stream_get_buffer_used_size(jsonl_ostream),
				o_stream_get_error(jsonl_ostream));
		o_stream_destroy(&jsonl_ostream);
	}
}

static bool
jsonl_is_initialized(void)
{
	return jsonl_ostream != NULL;
}

static const struct imaptest_exporter_driver jsonl_driver = {
	.name = "jsonl",
	.init = jsonl_init,
	.deinit = jsonl_deinit,
	.is_initialized = jsonl_is_initialized,
};

void
imaptest_exporter_jsonl_register(void)
{
	imaptest_exporter_register_driver(&jsonl_driver);
}

static const char *
jsonl_event_type_name(enum event_type type)
{
	switch (type) {
	case EVENT_TYPE_CMD_COMPLETED:	return "cmd_completed";
	case EVENT_TYPE_CLIENT_CONNECTED:	return "client_connected";
	case EVENT_TYPE_CLIENT_DISCONNECTED:	return "client_disconnected";
	case EVENT_TYPE_INTERVAL_STATS:	return "interval_stats";
	case EVENT_TYPE_TEST_RESULT:	return "test_result";
	case EVENT_TYPE_TEST_SUMMARY:	return "test_summary";
	case EVENT_TYPE_CLIENT_STALLED:	return "client_stalled";
	case EVENT_TYPE_CHECKPOINT_ERROR:	return "checkpoint_error";
	default:			return "unknown";
	}
}

static struct jsonl_event *jsonl_event_open(void)
{
	char buf[32];
	struct jsonl_event *je;
	struct timeval tv;

	je = t_new(struct jsonl_event, 1);
	je->line = t_str_new(256);
	je->gen = json_generator_init_str(je->line, 0);

	json_generate_object_open(je->gen);

	i_gettimeofday(&tv);

	i_snprintf(buf, sizeof(buf), "%ld.%06ld", (long)tv.tv_sec,
			(long)tv.tv_usec);

	(void)json_generate_object_member(je->gen, "ts");
	(void)json_generate_number_raw(je->gen, buf);

	return je;
}

static void
jsonl_event_close(struct jsonl_event *je)
{
	(void)json_generate_object_close(je->gen);
	json_generator_deinit(&je->gen);

	str_append_c(je->line, '\n');

	/* NOTE: Each event triggers a write + flush. This is correct for
	 * crash-safety (events are immediately visible) but not optimal
	 * for high-throughput scenarios (100+ concurrent clients). */
	o_stream_nsend(jsonl_ostream, str_data(je->line), str_len(je->line));
	if (o_stream_flush(jsonl_ostream) < 0)
		i_error("Failed to write JSONL event: %s",
			o_stream_get_error(jsonl_ostream));
}

static void
jsonl_serialize_event(const struct imaptest_event *ev)
{
	struct jsonl_event *je = jsonl_event_open();

	JSON_GEN_STRING(je, "event", jsonl_event_type_name(ev->type));

	switch (ev->type) {
	case EVENT_TYPE_CMD_COMPLETED:
		JSON_GEN_NUMBER(je, "client_id", ev->u.cmd_completed.client_id);
		JSON_GEN_STRING(je, "username", ev->u.cmd_completed.username);
		JSON_GEN_STRING(je, "protocol", ev->u.cmd_completed.protocol);
		JSON_GEN_STRING(je, "state", ev->u.cmd_completed.state);
		JSON_GEN_STRING(je, "reply", ev->u.cmd_completed.reply);
		JSON_GEN_NUMBER(je, "duration_usecs", ev->u.cmd_completed.duration_usecs);
		JSON_GEN_STRING(je, "mailbox", ev->u.cmd_completed.mailbox);
		JSON_GEN_NUMBER(je, "tag", ev->u.cmd_completed.tag);
		break;

	case EVENT_TYPE_CLIENT_CONNECTED:
		JSON_GEN_NUMBER(je, "client_id", ev->u.client_connected.client_id);
		JSON_GEN_STRING(je, "username", ev->u.client_connected.username);
		JSON_GEN_STRING(je, "protocol", ev->u.client_connected.protocol);
		JSON_GEN_NUMBER(je, "port", ev->u.client_connected.port);
		break;

	case EVENT_TYPE_CLIENT_DISCONNECTED:
		JSON_GEN_NUMBER(je, "client_id", ev->u.client_disconnected.client_id);
		JSON_GEN_STRING(je, "username", ev->u.client_disconnected.username);
		JSON_GEN_STRING(je, "reason", ev->u.client_disconnected.reason);
		JSON_GEN_NUMBER(je, "duration_usecs", ev->u.client_disconnected.duration_usecs);
		break;

	case EVENT_TYPE_INTERVAL_STATS:
		JSON_GEN_NUMBER(je, "active_clients", ev->u.interval_stats.active_clients);
		JSON_GEN_NUMBER(je, "total_clients", ev->u.interval_stats.total_clients);
		JSON_GEN_NUMBER(je, "stalled_count", ev->u.interval_stats.stalled_count);
		JSON_GEN_NUMBER(je, "total_disconnects", ev->u.interval_stats.total_disconnects);
		for (unsigned int i = 1; i < STATE_COUNT; i++) {
			char name_buf[128];
			unsigned long long avg;

			if (!STATE_IS_VISIBLE_AT(i))
				continue;

			i_snprintf(name_buf, sizeof(name_buf), "%s_count",
					states[i].name);
			JSON_GEN_NUMBER(je, name_buf, ev->u.interval_stats.counters[i]);

			avg = 0;
			if (ev->u.interval_stats.timer_counts[i] > 0)
				avg = ev->u.interval_stats.timers[i] / ev->u.interval_stats.timer_counts[i];
			i_snprintf(name_buf, sizeof(name_buf), "%s_avg_msecs",
					states[i].name);
			JSON_GEN_NUMBER(je, name_buf, avg);
		}
		break;

	case EVENT_TYPE_TEST_RESULT:
		JSON_GEN_STRING(je, "test_name", ev->u.test_result.test_name);
		JSON_GEN_BOOL(je, "passed", ev->u.test_result.passed);
		JSON_GEN_BOOL(je, "skipped", ev->u.test_result.skipped);
		JSON_GEN_STRING(je, "failure_reason", ev->u.test_result.failure_reason);
		break;

	case EVENT_TYPE_TEST_SUMMARY:
		JSON_GEN_NUMBER(je, "total_groups", ev->u.test_summary.total_groups);
		JSON_GEN_NUMBER(je, "group_failures", ev->u.test_summary.group_failures);
		JSON_GEN_NUMBER(je, "group_skips", ev->u.test_summary.group_skips);
		JSON_GEN_NUMBER(je, "base_failures", ev->u.test_summary.base_failures);
		JSON_GEN_NUMBER(je, "base_tests", ev->u.test_summary.base_tests);
		JSON_GEN_NUMBER(je, "ext_failures", ev->u.test_summary.ext_failures);
		JSON_GEN_NUMBER(je, "ext_tests", ev->u.test_summary.ext_tests);
		break;

	case EVENT_TYPE_CLIENT_STALLED:
		JSON_GEN_NUMBER(je, "client_id", ev->u.client_stalled.client_id);
		JSON_GEN_STRING(je, "username", ev->u.client_stalled.username);
		JSON_GEN_NUMBER(je, "stalled_secs", ev->u.client_stalled.stalled_secs);
		JSON_GEN_STRING(je, "state", ev->u.client_stalled.state);
		break;

	case EVENT_TYPE_CHECKPOINT_ERROR:
		JSON_GEN_NUMBER(je, "client_id", ev->u.checkpoint_error.client_id);
		JSON_GEN_STRING(je, "username", ev->u.checkpoint_error.username);
		JSON_GEN_STRING(je, "mailbox", ev->u.checkpoint_error.mailbox);
		JSON_GEN_STRING(je, "detail", ev->u.checkpoint_error.detail);
		break;

	default:
		break;
	}

	jsonl_event_close(je);
}

void
imaptest_event_generate(const struct imaptest_event *ev)
{
	if (!imaptest_exporter_is_initialized())
		return;

	jsonl_serialize_event(ev);
}
