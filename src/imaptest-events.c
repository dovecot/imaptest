/* Copyright (c) ImapTest authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "imaptest-events.h"
#include "imaptest-exporter-jsonl.h"

void
imaptest_event_cmd_completed(struct imaptest_event *ev,
        unsigned int client_id, const char *username,
        const char *protocol, const char *state,
        const char *reply, long long duration_usecs,
        const char *mailbox, unsigned int tag)
{
	*ev = (struct imaptest_event){
		.type = EVENT_TYPE_CMD_COMPLETED,
		.u.cmd_completed = {
			.client_id = client_id,
			.username = username,
			.protocol = protocol,
			.state = state,
			.reply = reply,
			.duration_usecs = duration_usecs,
			.mailbox = mailbox,
			.tag = tag,
		}
	};

	imaptest_event_generate(ev);
}

void
imaptest_event_client_connected(struct imaptest_event *ev,
    unsigned int client_id, const char *username,
    const char *protocol, unsigned int port)
{
	*ev = (struct imaptest_event){
		.type = EVENT_TYPE_CLIENT_CONNECTED,
		.u.client_connected = {
			.client_id = client_id,
			.username = username,
			.protocol = protocol,
			.port = port,
		}
	};

	imaptest_event_generate(ev);
}

void
imaptest_event_client_disconnected(struct imaptest_event *ev,
       unsigned int client_id, const char *username,
       const char *reason, long long duration_usecs)
{
	*ev = (struct imaptest_event){
		.type = EVENT_TYPE_CLIENT_DISCONNECTED,
		.u.client_disconnected = {
			.client_id = client_id,
			.username = username,
			.reason = reason,
			.duration_usecs = duration_usecs,
		}
	};

	imaptest_event_generate(ev);
}

void
imaptest_event_interval_stats(struct imaptest_event *ev,
         unsigned int active_clients, unsigned int total_clients,
         unsigned int stalled_count, unsigned int total_disconnects,
         unsigned int state_count,
         const unsigned int *counters,
         const unsigned long long *timers,
         const unsigned int *timer_counts)
{
	*ev = (struct imaptest_event){
		.type = EVENT_TYPE_INTERVAL_STATS,
		.u.interval_stats = {
			.active_clients = active_clients,
			.total_clients = total_clients,
			.stalled_count = stalled_count,
			.total_disconnects = total_disconnects,
			.state_count = state_count,
			.counters = counters,
			.timers = timers,
			.timer_counts = timer_counts,
		}
	};

	imaptest_event_generate(ev);
}

void
imaptest_event_test_result(struct imaptest_event *ev,
      const char *test_name, bool passed, bool skipped,
      const char *failure_reason)
{
	*ev = (struct imaptest_event){
		.type = EVENT_TYPE_TEST_RESULT,
		.u.test_result = {
			.test_name = test_name,
			.passed = passed,
			.skipped = skipped,
			.failure_reason = failure_reason,
		}
	};

	imaptest_event_generate(ev);
}

void
imaptest_event_test_summary(struct imaptest_event *ev,
       unsigned int total_groups, unsigned int group_failures,
       unsigned int group_skips, unsigned int base_failures,
       unsigned int base_tests, unsigned int ext_failures,
       unsigned int ext_tests)
{
	*ev = (struct imaptest_event){
		.type = EVENT_TYPE_TEST_SUMMARY,
		.u.test_summary = {
			.total_groups = total_groups,
			.group_failures = group_failures,
			.group_skips = group_skips,
			.base_failures = base_failures,
			.base_tests = base_tests,
			.ext_failures = ext_failures,
			.ext_tests = ext_tests,
		}
	};

	imaptest_event_generate(ev);
}

void
imaptest_event_stall_detected(struct imaptest_event *ev,
         unsigned int client_id, const char *username,
         unsigned int stalled_secs, const char *state)
{
	*ev = (struct imaptest_event){
		.type = EVENT_TYPE_CLIENT_STALLED,
		.u.client_stalled = {
			.client_id = client_id,
			.username = username,
			.stalled_secs = stalled_secs,
			.state = state,
		}
	};

	imaptest_event_generate(ev);
}

void
imaptest_event_checkpoint_error(struct imaptest_event *ev,
    unsigned int client_id, const char *username,
    const char *mailbox, const char *detail)
{
	*ev = (struct imaptest_event){
		.type = EVENT_TYPE_CHECKPOINT_ERROR,
		.u.checkpoint_error = {
			.client_id = client_id,
			.username = username,
			.mailbox = mailbox,
			.detail = detail,
		}
	};

	imaptest_event_generate(ev);
}
