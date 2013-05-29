#ifndef TEST_PARSER_H
#define TEST_PARSER_H

#include "client-state.h"

enum test_startup_state {
	TEST_STARTUP_STATE_NONAUTH,
	/* auth is currently only an internal state. we make sure to delete all
	   mailboxes after auth. */
	TEST_STARTUP_STATE_AUTH,
	TEST_STARTUP_STATE_DELETED,
	TEST_STARTUP_STATE_CREATED,
	TEST_STARTUP_STATE_APPENDED,
	TEST_STARTUP_STATE_SELECTED
};

struct test_untagged {
	const struct imap_arg *args;

	unsigned int not_found:1;
};

struct test_command {
	/* line number in configuration file */
	unsigned int linenum;

	/* tag number used in the script (0 = no tag) */
	unsigned int tag;
	/* the actual tag sent to the IMAP server */
	unsigned int cur_cmd_tag;

	/* Command to execute */
	const char *command;
	unsigned int command_len;
	/* Expected tagged reply prefix */
	const struct imap_arg *reply;
};

struct test_command_group {
	/* Connection index which runs this command (0..connection_count-1) */
	unsigned int connection_idx;

	/* List of commands to send */
	ARRAY(struct test_command) commands;
	/* Expected untagged replies */
	ARRAY(struct test_untagged) untagged;

	/* Number of commands still missing a reply (0 once finished parsing) */
	unsigned int replies_pending;
};

struct test_connection {
	const char *username;
};

struct test {
	const char *name, *path;

	/* Path to mbox file to be used as the test's mailbox */
	const char *mbox_source_path;
	/* NULL-terminated list of IMAP capabilities required from the server */
	const char *const *required_capabilities;
	/* Number of messages to APPEND initially (-1 = all) */
	unsigned int message_count;
	/* Startup state in which this test is run */
	enum test_startup_state startup_state;

	/* Number of connections to use */
	unsigned int connection_count;
	/* Configuration to connections (may have less than connection_count) */
	ARRAY(struct test_connection) connections;

	/* List of commands to run for this test */
	ARRAY(struct test_command_group *) cmd_groups;

	unsigned int require_user2:1;
};
ARRAY_DEFINE_TYPE(test, struct test *);

struct test_parser *test_parser_init(const char *dir);
void test_parser_deinit(struct test_parser **parser);

/* Return an array of tests. They're freed when the parser is deinitialized. */
const ARRAY_TYPE(test) *test_parser_get_tests(struct test_parser *parser);

ARRAY_TYPE(imap_arg_list) *
test_parse_imap_args(pool_t pool, const char *line, unsigned int linelen,
		     const char **error_r);

#endif
