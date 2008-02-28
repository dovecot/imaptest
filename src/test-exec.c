/* Copyright (C) 2007 Timo Sirainen */

#include "lib.h"
#include "ioloop.h"
#include "hash.h"
#include "str.h"
#include "imap-parser.h"
#include "mailbox.h"
#include "mailbox-source.h"
#include "client.h"
#include "commands.h"
#include "imap-args.h"
#include "test-parser.h"
#include "test-exec.h"

#include <stdlib.h>
#include <ctype.h>

enum test_mailbox_state {
	TEST_MAILBOX_STATE_DELETE,
	TEST_MAILBOX_STATE_CREATE,
	TEST_MAILBOX_STATE_APPEND,
	TEST_MAILBOX_STATE_DONE
};

struct tests_execute_context {
	const ARRAY_TYPE(test) *tests;
	unsigned int next_test;
	unsigned int failures;
};

struct test_exec_context {
	pool_t pool;

	struct tests_execute_context *exec_ctx;
	const struct test *test;

	/* current command index */
	unsigned int cur_cmd_idx;
	unsigned int cur_untagged_mismatch_count;
	struct command *cur_cmd;
	buffer_t *cur_received_untagged;
	/* initial sequence -> current sequence (0=expunged) mapping */
	ARRAY_DEFINE(cur_seqmap, uint32_t);

	struct client **clients;
	struct mailbox_source *source;
	unsigned int clients_waiting, disconnects_waiting;

	struct hash_table *variables;
	ARRAY_DEFINE(added_variables, const char *);

	enum test_mailbox_state mailbox_state;
	unsigned int failed:1;
	unsigned int finished:1;
};

static void test_execute_free(struct test_exec_context *ctx);
static void test_execute_finish(struct test_exec_context *ctx);
static void test_send_next_command(struct test_exec_context *ctx);

static bool test_imap_match_args(struct test_exec_context *ctx,
				 const struct imap_arg *match,
				 const struct imap_arg *args,
				 unsigned int max, bool prefix);

static void ATTR_FORMAT(2, 3)
test_fail(struct test_exec_context *ctx, const char *fmt, ...)
{
	struct test_command *const *cmdp;
	struct client *client;
	va_list args;

	cmdp = array_idx(&ctx->test->commands, ctx->cur_cmd_idx);
	client = ctx->clients[(*cmdp)->connection_idx];

	va_start(args, fmt);
	i_error("Test %s command %u/%u failed: %s\n"
		" - Command (tag %u.%u): %s", ctx->test->name,
		ctx->cur_cmd_idx+1, array_count(&ctx->test->commands),
		t_strdup_vprintf(fmt, args),
		client->global_id, ctx->cur_cmd->tag, (*cmdp)->command);
	va_end(args);

	ctx->failed = TRUE;
}

static const char *
test_expand_relative_seq(struct test_exec_context *ctx, uint32_t seq)
{
	const uint32_t *seqs;
	unsigned int count;

	if (seq == 0)
		return "<zero seq>";

	seqs = array_get(&ctx->cur_seqmap, &count);
	if (seq > count)
		return "<out of range>";
	if (seqs[seq-1] == 0)
		return "<expunged>";
	return dec2str(seqs[seq-1]);
}

static const char *
test_expand_one(struct test_exec_context *ctx, const char *str,
		const char *input)
{
	const char *ckey;
	char *key, *value;

	if (*str != '$')
		return str;
	if (*++str == '$')
		return str;

	if (is_numeric(str, '\0')) {
		/* relative sequence */
		return test_expand_relative_seq(ctx, atoi(str));
	}

	/* variable support */
	value = hash_lookup(ctx->variables, str);
	if (value == NULL) {
		key = p_strdup(ctx->pool, str);
		value = p_strdup(ctx->pool, input);
		hash_insert(ctx->variables, key, value);

		ckey = key;
		array_append(&ctx->added_variables, &ckey, 1);
	}
	return value;
}

static const char *
test_expand_all(struct test_exec_context *ctx, const char *str)
{
	string_t *value;
	const char *p, *var_name, *var_value;

	p = strchr(str, '$');
	if (p == NULL)
		return str;

	/* need to expand variables */
	value = t_str_new(256);
	str_append_n(value, str, p-str);
	for (str = p; *str != '\0'; str++) {
		if (*str != '$' || str[1] == '\0')
			str_append_c(value, *str);
		else if (*++str == '$') {
			str_append_c(value, *str);
		} else if (*str == '!') {
			/* skip directives */
			while (str[1] != ' ' && str[1] != '\0') str++;
		} else {
			if (*str == '{') {
				p = strchr(++str, '}');
				if (p == NULL) {
					test_fail(ctx, "Missing '}'");
					break;
				}
				var_name = t_strdup_until(str, p++);
			} else {
				for (p = str; i_isalnum(*p); p++) ;
				var_name = t_strdup_until(str, p);
			}

			if (is_numeric(var_name, '\0')) {
				/* relative sequence */
				var_value = test_expand_relative_seq(ctx,
								     atoi(str));
			} else {
				var_value = hash_lookup(ctx->variables, var_name);
				if (var_value == NULL) {
					test_fail(ctx,
						  "Uninitialized variable: %s",
						  var_name);
					break;
				}
			}
			str_append(value, var_value);
			str = p - 1;
		}
	}
	return str_c(value);
}

static bool test_imap_match_list(struct test_exec_context *ctx,
				 const struct imap_arg *match,
				 const struct imap_arg *args)
{
	bool unordered = FALSE;
	unsigned int chain_count = 1;
	const char *str;
	unsigned int i, arg_count;
	buffer_t *matchbuf;
	unsigned char *matches;
	int noextra = -1;

	/* get $! directives */
	for (; match->type == IMAP_ARG_ATOM; match++) {
		str = IMAP_ARG_STR(match);
		if (strncmp(str, "$!", 2) != 0)
			break;

		str += 2;
		if (strncmp(str, "unordered", 9) == 0) {
			unordered = TRUE;
			if (noextra == -1)
				noextra = 0;
			if (str[9] == '=')
				chain_count = strtoul(str+10, NULL, 10);
		} else if (strcmp(str, "ordered") == 0) {
			unordered = FALSE;
		} else if (strcmp(str, "extra") == 0) {
			noextra = 0;
		} else if (strcmp(str, "noextra") == 0) {
			noextra = 1;
		} else {
			/* we should have caught this in parser */
			i_panic("Unknown directive: %s", str-2);
		}
	}
	if (noextra == -1)
		noextra = 1;

	if (!unordered) {
		/* full matching */
		return test_imap_match_args(ctx, match, args, -1U, FALSE);
	}

	/* sanity check - parser should check this already */
	for (i = 0; match[i].type != IMAP_ARG_EOL; i++) ;
	i_assert(i % chain_count == 0);

	/* make sure input has the correct argument i */
	for (i = 0; args[i].type != IMAP_ARG_EOL; i++) ;
	arg_count = i;

	if (arg_count % chain_count != 0) {
		/* non-even input argument count, can't match */
		return FALSE;
	}

	/* try to find each chain separately */
	matchbuf = buffer_create_dynamic(pool_datastack_create(), arg_count);
	matches = buffer_append_space_unsafe(matchbuf, arg_count);
	for (; match->type != IMAP_ARG_EOL; match += chain_count) {
		for (i = 0; i < arg_count; i += chain_count) {
			if (test_imap_match_args(ctx, match, &args[i],
						 chain_count, FALSE)) {
				matches[i] = 1;
				break;
			}
		}
		if (i == arg_count) {
			/* not found */
			return FALSE;
		}
	}
	if (noextra) {
		/* make sure everything got matched */
		for (i = 0; i < arg_count; i += chain_count) {
			if (matches[i] == 0)
				return FALSE;
		}
	}
	return TRUE;
}

static bool test_imap_match_args(struct test_exec_context *ctx,
				 const struct imap_arg *match,
				 const struct imap_arg *args,
				 unsigned int max, bool prefix)
{
	const char *mstr, *astr;

	for (; match->type != IMAP_ARG_EOL && max > 0; match++, args++, max--) {
		switch (match->type) {
		case IMAP_ARG_NIL:
			if (args->type != IMAP_ARG_NIL)
				return FALSE;
			break;
		case IMAP_ARG_ATOM:
		case IMAP_ARG_STRING:
		case IMAP_ARG_LITERAL:
			if (args->type == IMAP_ARG_LITERAL_SIZE) {
				/* shouldn't get here */
				i_panic("Test failed because args "
					"contain literal size");
			}

			if (!IMAP_ARG_TYPE_IS_STRING(args->type))
				return FALSE;
			astr = IMAP_ARG_STR(args);
			mstr = test_expand_one(ctx, IMAP_ARG_STR(match), astr);
			if (prefix && match[1].type == IMAP_ARG_EOL) {
				if (strncasecmp(astr, mstr, strlen(mstr)) != 0)
					return FALSE;
			} else {
				if (strcasecmp(astr, mstr) != 0)
					return FALSE;
			}
			break;
		case IMAP_ARG_LIST:
			if (args->type != IMAP_ARG_LIST)
				return FALSE;
			if (!test_imap_match_list(ctx,
						  IMAP_ARG_LIST_ARGS(match),
						  IMAP_ARG_LIST_ARGS(args)))
				return FALSE;
			break;
		case IMAP_ARG_LITERAL_SIZE:
		case IMAP_ARG_LITERAL_SIZE_NONSYNC:
			i_panic("Match args contain literal size");
			break;
		case IMAP_ARG_EOL:
			i_unreached();
		}
	}
	return prefix || args->type == IMAP_ARG_EOL || max == 0;
}

static void test_handle_expunge(struct test_exec_context *ctx, uint32_t seq)
{
	uint32_t *seqs;
	unsigned int i, count;

	seqs = array_get_modifiable(&ctx->cur_seqmap, &count);
	if (seq > count) {
		/* ignore sequences larger than our initial count.
		   they may come after EXISTS. */
		return;
	}
	/* find the sequence we're expunging */
	for (i = seq-1; i < count; i++) {
		if (seqs[i] >= seq) {
			if (seqs[i] == seq) {
				/* mark this one expunged */
				seqs[i] = 0;
			} else {
				/* update the larger sequences */
				seqs[i]--;
			}
		}
	}
}

static void
test_handle_untagged_match(struct client *client, const struct imap_arg *args)
{
	struct test_exec_context *ctx = client->test_exec_ctx;
	struct test_command *const *cmdp;
	const struct imap_arg *const *untagged;
	unsigned char *found;
	unsigned int i, count;
	bool prefix = FALSE;

	cmdp = array_idx(&ctx->test->commands, ctx->cur_cmd_idx);
	if (!array_is_created(&(*cmdp)->untagged)) {
		/* no untagged replies defined for the command.
		   don't bother checking further */
		return;
	}

	if (args->type == IMAP_ARG_ATOM) {
		const char *str = IMAP_ARG_STR(args);

		if (strcasecmp(str, "ok") == 0 ||
		    strcasecmp(str, "no") == 0 ||
		    strcasecmp(str, "bad") == 0) {
			/* these will have human-readable text appended after
			   [resp-text-code] */
			prefix = TRUE;
		}
	}

	array_clear(&ctx->added_variables);
	untagged = array_get(&(*cmdp)->untagged, &count);
	found = buffer_get_space_unsafe(ctx->cur_received_untagged, 0, count);
	for (i = 0; i < count; i++) {
		if (found[i] != 0)
			continue;

		if (test_imap_match_args(ctx, untagged[i], args, -1U, prefix)) {
			found[i] = 1;
			break;
		} else {
			/* if any variables were added, revert them */
			const char *const *vars;
			unsigned int j, var_count;

			vars = array_get(&ctx->added_variables, &var_count);
			for (j = 0; j < var_count; j++)
				hash_remove(ctx->variables, vars[j]);
			array_clear(&ctx->added_variables);
		}
	}
	if (i == count)
		ctx->cur_untagged_mismatch_count++;
}

static int
test_handle_untagged(struct client *client, const struct imap_arg *args)
{
	if (client_handle_untagged(client, args) < 0)
		return -1;

	test_handle_untagged_match(client, args);

	if (args->type == IMAP_ARG_ATOM && args[1].type == IMAP_ARG_ATOM &&
	    strcasecmp(args[1]._data.str, "expunge") == 0) {
		/* expunge: update sequence mapping. do this after matching
		   expunges above. */
		uint32_t seq = strtoul(args->_data.str, NULL, 10);

		test_handle_expunge(client->test_exec_ctx, seq);
	}
	return 0;
}

static void test_cmd_callback(struct client *client,
			      struct command *command ATTR_UNUSED,
			      const struct imap_arg *args,
			      enum command_reply reply)
{
	struct test_exec_context *ctx = client->test_exec_ctx;
	struct test_command *const *cmdp;
	const struct test_command *cmd;
	const unsigned char *found;
	unsigned int i, first_missing_idx, missing_count;

	i_assert(reply != REPLY_CONT);

	cmdp = array_idx(&ctx->test->commands, ctx->cur_cmd_idx);
	cmd = *cmdp;

	if (!test_imap_match_args(ctx, cmd->reply, args, -1U, TRUE)) {
		test_fail(ctx, "Expected tagged reply '%s', got '%s'",
			  imap_args_to_str(cmd->reply),
			  imap_args_to_str(args));
	} else if (array_is_created(&cmd->untagged)) {
		first_missing_idx = ctx->cur_received_untagged->used + 1;
		missing_count = 0;
		found = ctx->cur_received_untagged->data;
		for (i = 0; i < ctx->cur_received_untagged->used; i++) {
			if (found[i] == 0) {
				if (i < first_missing_idx)
					first_missing_idx = i;
				missing_count++;
			}
		}
		missing_count += ctx->cur_received_untagged->used -
			array_count(&cmd->untagged);

		if (missing_count != 0) {
			const struct imap_arg *const *uarg =
				array_idx(&cmd->untagged, first_missing_idx);

			test_fail(ctx, "Missing %u untagged replies "
				  "(%u mismatches)\n"
				  " - first unexpanded: %s\n"
				  " - first expanded: %s", missing_count,
				  ctx->cur_untagged_mismatch_count,
				  imap_args_to_str(*uarg),
				  test_expand_all(ctx, imap_args_to_str(*uarg)));
		}
	}

	ctx->cur_cmd_idx++;
	test_send_next_command(ctx);
}

static void test_send_next_command(struct test_exec_context *ctx)
{
	struct test_command *const *cmdp;
	struct client *client;
	const char *cmdline;
	uint32_t seq;

	ctx->cur_cmd = NULL;

	if (ctx->cur_cmd_idx == array_count(&ctx->test->commands)) {
		test_execute_finish(ctx);
		return;
	}
	cmdp = array_idx(&ctx->test->commands, ctx->cur_cmd_idx);
	client = ctx->clients[(*cmdp)->connection_idx];

	ctx->cur_untagged_mismatch_count = 0;
	buffer_reset(ctx->cur_received_untagged);

	/* create initial sequence map */
	array_clear(&ctx->cur_seqmap);
	for (seq = 1; seq <= array_count(&client->view->uidmap); seq++)
		array_append(&ctx->cur_seqmap, &seq, 1);

	cmdline = test_expand_all(ctx, (*cmdp)->command);
	if (strcasecmp(cmdline, "append") == 0) {
		client->state = STATE_APPEND;
		(void)client_append(client, FALSE, FALSE);
	} else {
		ctx->cur_cmd = command_send(client, cmdline, test_cmd_callback);
	}
}

static int test_send_no_commands(struct client *client)
{
	struct test_exec_context *ctx = client->test_exec_ctx;

	if (client->state == STATE_APPEND) {
		/* we just executed an APPEND */
		i_assert(!client->append_unfinished);
		ctx->cur_cmd_idx++;
		client->state = STATE_SELECT;
		test_send_next_command(ctx);
	}
	return 0;
}

static void test_send_first_command(struct test_exec_context *ctx)
{
	unsigned int i;

	/* there will be no automatic command sending */
	for (i = 0; i < ctx->test->connection_count; i++)
		ctx->clients[i]->send_more_commands = test_send_no_commands;

	test_send_next_command(ctx);
}

static int test_send_lstate_commands(struct client *client)
{
	struct test_exec_context *ctx = client->test_exec_ctx;
	const char *str;
	unsigned int i;

	i_assert(ctx->clients_waiting > 0);

	if (client->login_state == ctx->test->login_state) {
		/* we're in the wanted state */
		if (--ctx->clients_waiting == 0)
			test_send_first_command(ctx);

		if (client == ctx->clients[0] &&
		    client->login_state == LSTATE_SELECTED) {
			/* if any other clients were waiting on us,
			   resume them */
			for (i = 1; i < ctx->test->connection_count; i++) {
				if (ctx->clients[i]->state != STATE_SELECT)
					continue;

				test_send_lstate_commands(ctx->clients[i]);
			}
		}
		return 0;
	}

	client->plan_size = 0;
	switch (client->login_state) {
	case LSTATE_NONAUTH:
		client->plan[0] = STATE_LOGIN;
		client->plan_size = 1;
		break;
	case LSTATE_AUTH:
		if (ctx->mailbox_state == TEST_MAILBOX_STATE_DONE) {
			if (client != ctx->clients[0]) {
				client->plan[0] = STATE_SELECT;
				client->plan_size = 1;
				break;
			}
			break;
		}
		/* the first client will delete and recreate the mailbox */
		if (client != ctx->clients[0]) {
			/* wait until the mailbox is created */
			client->state = STATE_SELECT;
			break;
		}

		switch (ctx->mailbox_state) {
		case TEST_MAILBOX_STATE_DELETE:
			client->state = STATE_MDELETE;
			str = t_strdup_printf("DELETE \"%s\"",
					      client->view->storage->name);
			ctx->mailbox_state++;
			command_send(client, str, state_callback);
			break;
		case TEST_MAILBOX_STATE_CREATE:
			client->state = STATE_MCREATE;
			str = t_strdup_printf("CREATE \"%s\"",
					      client->view->storage->name);
			ctx->mailbox_state++;
			command_send(client, str, state_callback);
			break;
		case TEST_MAILBOX_STATE_APPEND:
			if (!mailbox_source_eof(ctx->source)) {
				client->state = STATE_APPEND;
				if (client_append(client, FALSE, FALSE) < 0)
					return -1;
				break;
			}
			/* finished. select the mailbox so we have the
			   messages recent. */
			ctx->mailbox_state++;
			client->plan[0] = STATE_SELECT;
			client->plan_size = 1;
			break;
		case TEST_MAILBOX_STATE_DONE:
			i_unreached();
		}
		break;
	case LSTATE_SELECTED:
		i_unreached();
	}
	if (client->plan_size > 0)
		(void)client_plan_send_next_cmd(client);
	return 0;
}

static int test_execute(const struct test *test,
			struct tests_execute_context *exec_ctx)
{
	struct test_exec_context *ctx;
	unsigned int i;
	pool_t pool;

	pool = pool_alloconly_create("test exec context", 1024);
	ctx = p_new(pool, struct test_exec_context, 1);
	ctx->pool = pool;
	ctx->test = test;
	ctx->exec_ctx = exec_ctx;
	ctx->source = mailbox_source_new(test->mbox_source_path);
	ctx->cur_received_untagged =
		buffer_create_dynamic(default_pool, 128);
	ctx->variables = hash_create(default_pool, pool, 0, str_hash,
				     (hash_cmp_callback_t *)strcmp);
	p_array_init(&ctx->added_variables, pool, 32);
	i_array_init(&ctx->cur_seqmap, 128);

	/* create clients for the test */
	ctx->clients = p_new(pool, struct client *, test->connection_count);
	for (i = 0; i < test->connection_count; i++) {
		ctx->clients[i] = client_new(array_count(&clients),
					     ctx->source);
		if (ctx->clients[i] == NULL) {
			test_execute_free(ctx);
			return -1;
		}
		ctx->clients[i]->handle_untagged = test_handle_untagged;
		ctx->clients[i]->send_more_commands = test_send_lstate_commands;
		ctx->clients[i]->test_exec_ctx = ctx;
	}
	ctx->clients_waiting = test->connection_count;

	hash_insert(ctx->variables, "mailbox",
		    ctx->clients[0]->view->storage->name);
	return 0;
}

static void tests_execute_next(struct tests_execute_context *exec_ctx)
{
	const struct test *const *tests;
	unsigned int count;

	tests = array_get(exec_ctx->tests, &count);
	if (exec_ctx->next_test != count)
		test_execute(tests[exec_ctx->next_test++], exec_ctx);
	else {
		i_info("%u / %u tests failed", exec_ctx->failures, count);
		io_loop_stop(current_ioloop);
	}
}

struct tests_execute_context *tests_execute(const ARRAY_TYPE(test) *tests)
{
	struct tests_execute_context *ctx;

	ctx = i_new(struct tests_execute_context, 1);
	ctx->tests = tests;

	tests_execute_next(ctx);
	return ctx;
}

bool tests_execute_done(struct tests_execute_context **_ctx)
{
	struct tests_execute_context *ctx = *_ctx;
	bool ret = ctx->failures == 0;

	*_ctx = NULL;
	i_free(ctx);
	return ret;
}

static void test_execute_finish(struct test_exec_context *ctx)
{
	unsigned int i;

	i_assert(!ctx->finished);
	ctx->finished = TRUE;

	if (ctx->failed)
		ctx->exec_ctx->failures++;

	/* disconnect all clients */
	for (i = 0; i < ctx->test->connection_count; i++) {
		if (ctx->clients[i] != NULL)
			client_disconnect(ctx->clients[i]);
	}
	ctx->disconnects_waiting = ctx->test->connection_count;
}

static void test_execute_free(struct test_exec_context *ctx)
{
	array_free(&ctx->cur_seqmap);
	hash_destroy(&ctx->variables);
	mailbox_source_unref(&ctx->source);
	buffer_free(&ctx->cur_received_untagged);
	pool_unref(&ctx->pool);
}

void test_execute_cancel_by_client(struct client *client)
{
	struct test_exec_context *ctx = client->test_exec_ctx;
	struct tests_execute_context *exec_ctx = ctx->exec_ctx;
	unsigned int i;

	for (i = 0; i < ctx->test->connection_count; i++) {
		if (ctx->clients[i] == client)
			ctx->clients[i] = NULL;
	}

	if (ctx->disconnects_waiting == 0) {
		test_fail(ctx, "Unexpected disconnection");
		test_execute_finish(ctx);
		i_assert(ctx->disconnects_waiting > 0);
	}
	client->test_exec_ctx = NULL;

	if (--ctx->disconnects_waiting == 0) {
		test_execute_free(ctx);
		tests_execute_next(exec_ctx);
	}
}
