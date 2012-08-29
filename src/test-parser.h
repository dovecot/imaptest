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
	/* Connection index which runs this command (0..connection_count-1) */
	unsigned int connection_idx;
	/* line number in configuration file */
	unsigned int linenum;

	/* Command to execute */
	const char *command;
	/* Expected tagged reply prefix */
	const struct imap_arg *reply;

	/* Expected untagged replies */
	ARRAY(struct test_untagged) untagged;
};

struct test {
	const char *name, *path;

	/* Path to mbox file to be used as the test's mailbox */
	const char *mbox_source_path;
	/* NULL-terminated list of IMAP capabilities required from the server */
	const char *const *required_capabilities;
	/* Number of connections to use */
	unsigned int connection_count;
	/* Number of messages to APPEND initially (-1 = all) */
	unsigned int message_count;
	/* Startup state in which this test is run */
	enum test_startup_state startup_state;

	/* List of commands to run for this test */
	ARRAY(struct test_command *) commands;
};
ARRAY_DEFINE_TYPE(test, const struct test *);

struct test_parser *test_parser_init(const char *dir);
void test_parser_deinit(struct test_parser **parser);

/* Return an array of tests. They're freed when the parser is deinitialized. */
const ARRAY_TYPE(test) *test_parser_get_tests(struct test_parser *parser);

ARRAY_TYPE(imap_arg_list) *
test_parse_imap_args(pool_t pool, const char *line, const char **error_r);

#endif
