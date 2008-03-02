#ifndef TEST_PARSER_H
#define TEST_PARSER_H

#include "client-state.h"

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
	ARRAY_DEFINE(untagged, const struct imap_arg *);
};

struct test {
	const char *name, *path;

	/* Path to mbox file to be used as the test's mailbox */
	const char *mbox_source_path;
	/* NULL-terminated list of IMAP capabilities required from the server */
	const char *const *required_capabilities;
	/* Number of connections to use */
	unsigned int connection_count;
	/* Login state in which this command is run */
	enum login_state login_state;

	/* List of commands to run for this test */
	ARRAY_DEFINE(commands, struct test_command *);
};
ARRAY_DEFINE_TYPE(test, const struct test *);

struct test_parser *test_parser_init(const char *dir);
void test_parser_deinit(struct test_parser **parser);

/* Return an array of tests. They're freed when the parser is deinitialized. */
const ARRAY_TYPE(test) *test_parser_get_tests(struct test_parser *parser);

#endif
