/* Copyright (c) ImapTest authors, see the included COPYING file */

#ifndef IMAPTEST_EVENTS_H
#define IMAPTEST_EVENTS_H

#include "lib.h"

/* Event type enumeration — compile-time safe */
enum event_type {
	EVENT_TYPE_CMD_COMPLETED,
	EVENT_TYPE_CLIENT_CONNECTED,
	EVENT_TYPE_CLIENT_DISCONNECTED,
	EVENT_TYPE_INTERVAL_STATS,
	EVENT_TYPE_TEST_RESULT,
	EVENT_TYPE_TEST_SUMMARY,
	EVENT_TYPE_CLIENT_STALLED,
	EVENT_TYPE_CHECKPOINT_ERROR,

	EVENT_TYPE_COUNT
};

/* Union-based tagged struct grouping event-specific fields */
struct imaptest_event {
	enum event_type type;

	union {
		struct {
			unsigned int client_id;
			const char *username;
			const char *protocol;
			const char *state;
			const char *reply;
			long long duration_usecs;
			const char *mailbox;
			unsigned int tag;
		} cmd_completed;

		struct {
			unsigned int client_id;
			const char *username;
			const char *protocol;
			unsigned int port;
		} client_connected;

		struct {
			unsigned int client_id;
			const char *username;
			const char *reason;
			long long duration_usecs;
		} client_disconnected;

		struct {
			unsigned int active_clients;
			unsigned int total_clients;
			unsigned int stalled_count;
			unsigned int total_disconnects;
			unsigned int state_count;
			const unsigned int *counters;
			const unsigned long long *timers;
			const unsigned int *timer_counts;
		} interval_stats;

		struct {
			const char *test_name;
			bool passed;
			bool skipped;
			const char *failure_reason;
		} test_result;

		struct {
			unsigned int total_groups;
			unsigned int group_failures;
			unsigned int group_skips;
			unsigned int base_failures;
			unsigned int base_tests;
			unsigned int ext_failures;
			unsigned int ext_tests;
		} test_summary;

		struct {
			unsigned int client_id;
			const char *username;
			unsigned int stalled_secs;
			const char *state;
		} client_stalled;

		struct {
			unsigned int client_id;
			const char *username;
			const char *mailbox;
			const char *detail;
		} checkpoint_error;
	} u;
};

/* Command completions (IMAP & POP3) — primitive args, stateless */
void imaptest_event_cmd_completed(struct imaptest_event *ev,
      unsigned int client_id, const char *username,
      const char *protocol, const char *state,
      const char *reply, long long duration_usecs,
      const char *mailbox, unsigned int tag);

/* Client Lifecycle — primitive args, stateless */
void imaptest_event_client_connected(struct imaptest_event *ev,
         unsigned int client_id, const char *username,
         const char *protocol, unsigned int port);
void imaptest_event_client_disconnected(struct imaptest_event *ev,
     unsigned int client_id, const char *username,
     const char *reason, long long duration_usecs);

/* Periodic Aggregate Statistics — primitive args, stateless */
void imaptest_event_interval_stats(struct imaptest_event *ev,
       unsigned int active_clients, unsigned int total_clients,
       unsigned int stalled_count, unsigned int total_disconnects,
       unsigned int state_count,
       const unsigned int *counters,
       const unsigned long long *timers,
       const unsigned int *timer_counts);

/* Scripted Test Results & Summary — primitive args, stateless */
void imaptest_event_test_result(struct imaptest_event *ev,
    const char *test_name, bool passed, bool skipped,
    const char *failure_reason);
void imaptest_event_test_summary(struct imaptest_event *ev,
     unsigned int total_groups, unsigned int group_failures,
     unsigned int group_skips, unsigned int base_failures,
     unsigned int base_tests, unsigned int ext_failures,
     unsigned int ext_tests);

/* Diagnostics (Stalls & Checkpoint Errors) — primitive args, stateless */
void imaptest_event_stall_detected(struct imaptest_event *ev,
       unsigned int client_id, const char *username,
       unsigned int stalled_secs, const char *state);
void imaptest_event_checkpoint_error(struct imaptest_event *ev,
         unsigned int client_id, const char *username,
         const char *mailbox, const char *detail);

/* Generate and send — caller fills struct, this serializes via exporter */
void imaptest_event_generate(const struct imaptest_event *ev);

#endif /* IMAPTEST_EVENTS_H */
