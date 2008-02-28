/* Copyright (C) 2007 Timo Sirainen */

#include "lib.h"
#include "ioloop.h"
#include "imap-parser.h"
#include "mailbox.h"
#include "mailbox-source.h"
#include "client.h"
#include "commands.h"
#include "imap-args.h"
#include "test-parser.h"
#include "test-exec.h"

enum test_mailbox_state {
	TEST_MAILBOX_STATE_DELETE,
	TEST_MAILBOX_STATE_CREATE,
	TEST_MAILBOX_STATE_APPEND,
	TEST_MAILBOX_STATE_DONE
};

struct tests_iter_context {
	const ARRAY_TYPE(test) *tests;
	unsigned int next_test;
	unsigned int failures;
};

struct test_exec_context {
	pool_t pool;

	struct tests_iter_context *iter;
	const struct test *test;
	unsigned int cur_cmd;
	unsigned int cur_untagged_mismatch_count;
	buffer_t *cur_received_untagged;

	struct client **clients;
	struct mailbox_source *source;
	unsigned int clients_waiting, disconnects_waiting;

	enum test_mailbox_state mailbox_state;
	unsigned int failed:1;
	unsigned int finished:1;
};

static void test_execute_free(struct test_exec_context *ctx);
static void test_execute_finish(struct test_exec_context *ctx);
static void test_send_next_command(struct test_exec_context *ctx);

static const char *
test_expand_vars(struct test_exec_context *ctx ATTR_UNUSED, const char *str)
{
	/* FIXME: add support for variables */
	return str;
}

static bool test_imap_args_match(struct test_exec_context *ctx,
				 const struct imap_arg *match,
				 const struct imap_arg *args, bool prefix)
{
	const char *mstr, *astr;

	for (; match->type != IMAP_ARG_EOL; match++, args++) {
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
			mstr = test_expand_vars(ctx, IMAP_ARG_STR(match));
			astr = IMAP_ARG_STR(args);
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
			if (!test_imap_args_match(ctx,
						  IMAP_ARG_LIST_ARGS(match),
						  IMAP_ARG_LIST_ARGS(args),
						  FALSE))
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
	return prefix || args->type == IMAP_ARG_EOL;
}

static void ATTR_FORMAT(2, 3)
test_fail(struct test_exec_context *ctx, const char *fmt, ...)
{
	struct test_command *const *cmdp;
	va_list args;

	cmdp = array_idx(&ctx->test->commands, ctx->cur_cmd);

	va_start(args, fmt);
	i_error("Test %s command %u/%u failed: %s", ctx->test->name,
		ctx->cur_cmd+1, array_count(&ctx->test->commands),
		t_strdup_vprintf(fmt, args));
	i_error(" - Command: %s", (*cmdp)->command);
	va_end(args);

	ctx->failed = TRUE;
}

static int
test_handle_untagged(struct client *client, const struct imap_arg *args)
{
	struct test_exec_context *ctx = client->test_exec_ctx;
	struct test_command *const *cmdp;
	const struct imap_arg *const *untagged;
	unsigned char *found;
	unsigned int i, count;

	if (client_handle_untagged(client, args) < 0)
		return -1;
	cmdp = array_idx(&ctx->test->commands, ctx->cur_cmd);

	if (!array_is_created(&(*cmdp)->untagged))
		return 0;

	untagged = array_get(&(*cmdp)->untagged, &count);
	found = buffer_get_space_unsafe(ctx->cur_received_untagged, 0, count);
	for (i = 0; i < count; i++) {
		if (found[i] == 0 &&
		    test_imap_args_match(ctx, untagged[i], args, FALSE)) {
			found[i] = 1;
			break;
		}
	}
	if (i == count)
		ctx->cur_untagged_mismatch_count++;
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

	cmdp = array_idx(&ctx->test->commands, ctx->cur_cmd);
	cmd = *cmdp;

	if (!test_imap_args_match(ctx, cmd->reply, args, TRUE)) {
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
				  "(%u mismatches), first one: %s",
				  missing_count,
				  ctx->cur_untagged_mismatch_count,
				  imap_args_to_str(*uarg));
		}
	}

	ctx->cur_cmd++;
	test_send_next_command(ctx);
}

static void test_send_next_command(struct test_exec_context *ctx)
{
	struct test_command *const *cmdp;
	const char *cmdline;

	if (ctx->cur_cmd == array_count(&ctx->test->commands)) {
		test_execute_finish(ctx);
		return;
	}
	cmdp = array_idx(&ctx->test->commands, ctx->cur_cmd);

	ctx->cur_untagged_mismatch_count = 0;
	buffer_reset(ctx->cur_received_untagged);
	cmdline = test_expand_vars(ctx, (*cmdp)->command);
	command_send(ctx->clients[(*cmdp)->connection_idx],
		     cmdline, test_cmd_callback);
}

static int test_send_no_commands(struct client *client ATTR_UNUSED)
{
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
			i_assert(client != ctx->clients[0]);
			client->plan[0] = STATE_SELECT;
			client->plan_size = 1;
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
			/* finished. if any other clients were waiting on us,
			   resume them */
			for (i = 0; i < ctx->test->connection_count; i++) {
				if (ctx->clients[i]->state != STATE_SELECT)
					continue;

				i_assert(ctx->clients[i] != client);
				test_send_lstate_commands(ctx->clients[i]);
			}
			client->plan[0] = STATE_SELECT;
			client->plan_size = 1;
			ctx->mailbox_state++;
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
			struct tests_iter_context *iter)
{
	struct test_exec_context *ctx;
	unsigned int i;
	pool_t pool;

	pool = pool_alloconly_create("test exec context", 1024);
	ctx = p_new(pool, struct test_exec_context, 1);
	ctx->pool = pool;
	ctx->test = test;
	ctx->iter = iter;
	ctx->source = mailbox_source_new(test->mbox_source_path);
	ctx->cur_received_untagged =
		buffer_create_dynamic(default_pool, 128);

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
	return 0;
}

static void tests_execute_next(struct tests_iter_context *iter)
{
	const struct test *const *tests;
	unsigned int count;

	tests = array_get(iter->tests, &count);
	if (iter->next_test != count)
		test_execute(tests[iter->next_test++], iter);
	else {
		i_info("%u / %u tests failed", iter->failures, count);
		io_loop_stop(current_ioloop);
	}
}

void tests_execute(const ARRAY_TYPE(test) *tests)
{
	struct tests_iter_context *iter;

	iter = i_new(struct tests_iter_context, 1);
	iter->tests = tests;

	tests_execute_next(iter);
}

static void test_execute_finish(struct test_exec_context *ctx)
{
	unsigned int i;

	i_assert(!ctx->finished);
	ctx->finished = TRUE;

	if (ctx->failed)
		ctx->iter->failures++;

	/* disconnect all clients */
	for (i = 0; i < ctx->test->connection_count; i++) {
		if (ctx->clients[i] != NULL)
			client_disconnect(ctx->clients[i]);
	}
	ctx->disconnects_waiting = ctx->test->connection_count;
}

static void test_execute_free(struct test_exec_context *ctx)
{
	mailbox_source_unref(&ctx->source);
	buffer_free(&ctx->cur_received_untagged);
	pool_unref(&ctx->pool);
}

void test_execute_cancel_by_client(struct client *client)
{
	struct test_exec_context *ctx = client->test_exec_ctx;
	struct tests_iter_context *iter = ctx->iter;
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
		tests_execute_next(iter);
	}
}
