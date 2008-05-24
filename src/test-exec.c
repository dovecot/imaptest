/* Copyright (C) 2007 Timo Sirainen */

#include "lib.h"
#include "ioloop.h"
#include "hash.h"
#include "str.h"
#include "imap-quote.h"
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

struct tests_execute_context {
	const ARRAY_TYPE(test) *tests;
	unsigned int next_test;
	unsigned int failures;
};

struct test_maybe_match {
	const char *str;
	unsigned int count;
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
	ARRAY_DEFINE(cur_maybe_matches, struct test_maybe_match);
	/* initial sequence -> current sequence (0=expunged) mapping */
	ARRAY_DEFINE(cur_seqmap, uint32_t);

	struct client **clients;
	struct mailbox_source *source;
	unsigned int clients_waiting, disconnects_waiting;
	unsigned int appends_left;

	ARRAY_TYPE(const_string) delete_mailboxes, unsubscribe_mailboxes;
	unsigned int delete_refcount;

	struct hash_table *variables;
	ARRAY_DEFINE(added_variables, const char *);

	enum test_startup_state startup_state;
	unsigned int failed:1;
	unsigned int finished:1;
	unsigned int init_finished:1;
	unsigned int listing:1;
};

#define t_imap_quote_str(str) \
	imap_quote(pool_datastack_create(), (const void *)str, strlen(str))

static void init_callback(struct client *client, struct command *command,
			  const struct imap_arg *args,
			  enum command_reply reply);

static void test_execute_free(struct test_exec_context *ctx);
static void test_execute_finish(struct test_exec_context *ctx);
static void test_send_next_command(struct test_exec_context *ctx);
static int test_send_lstate_commands(struct client *client);

static unsigned int
test_imap_match_args(struct test_exec_context *ctx,
		     const struct imap_arg *match,
		     const struct imap_arg *args,
		     unsigned int max, bool prefix);

static void ATTR_FORMAT(2, 3)
test_fail(struct test_exec_context *ctx, const char *fmt, ...)
{
	struct test_command *const *cmdp;
	struct client *client;
	string_t *str;
	va_list args;

	cmdp = array_idx(&ctx->test->commands, ctx->cur_cmd_idx);
	client = ctx->clients[(*cmdp)->connection_idx];

	va_start(args, fmt);
	if (!ctx->init_finished) {
		i_error("Test %s initialization failed: %s",
			ctx->test->name, t_strdup_vprintf(fmt, args));
	} else {
		str = t_str_new(256);
		str_printfa(str, "Test %s command %u/%u (line %u) failed: %s\n"
			    " - Command", ctx->test->name, ctx->cur_cmd_idx+1,
			    array_count(&ctx->test->commands),
			    (*cmdp)->linenum, t_strdup_vprintf(fmt, args));
		if (ctx->cur_cmd != NULL && client != NULL) {
			str_printfa(str, " (tag %u.%u)",
				    client->global_id, ctx->cur_cmd->tag);
		}
		str_printfa(str, ": %s", (*cmdp)->command);
		i_error("%s", str_c(str));
	}
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
test_expand_all(struct test_exec_context *ctx, const char *str,
		bool skip_uninitialized)
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
				if (var_value == NULL && !skip_uninitialized) {
					test_fail(ctx,
						  "Uninitialized variable: %s",
						  var_name);
					break;
				} else if (var_value == NULL) {
					var_value = "$";
				}
			}
			str_append(value, var_value);
			str = p - 1;
		}
	}
	return str_c(value);
}

static const char *
test_expand_input(struct test_exec_context *ctx, const char *str,
		  const char *input)
{
	const char *p, *ckey, *value, *var_name, *tmp_str;
	char *key, *value2;
	string_t *output;

	output = t_str_new(128);
	for (; *str != '\0'; ) {
		if (*str != '$' || str[1] == '\0' || *++str == '$') {
			if (i_toupper(*str) != i_toupper(*input)) {
				/* mismatch already */
				return NULL;
			}
			input++;
			str_append_c(output, *str++);
			continue;
		}

		if (*str == '{') {
			p = strchr(str + 1, '}');
			if (p == NULL)
				return "";
			var_name = t_strdup_until(str + 1, p);
			str = p + 1;
		} else {
			for (p = str; i_isalnum(*p); p++) ;
			var_name = t_strdup_until(str, p);
			str = p;
		}

		if (is_numeric(var_name, '\0')) {
			/* relative sequence */
			value = test_expand_relative_seq(ctx, atoi(var_name));
		} else {
			value = hash_lookup(ctx->variables, var_name);
			if (value == NULL) {
				/* find how far we want to expand.
				   FIXME: for now we just check the first
				   letter */
				tmp_str = *str != '$' ? str :
					test_expand_input(ctx, str, input);
				p = input;
				while (i_toupper(*p) != i_toupper(*tmp_str) &&
				       *p != '\0')
					p++;

				key = p_strdup(ctx->pool, var_name);
				value2 = p_strdup_until(ctx->pool, input, p);
				hash_insert(ctx->variables, key, value2);

				ckey = key;
				value = value2;
				array_append(&ctx->added_variables, &ckey, 1);
			}
		}
		str_append(output, value);

		/* skip over value from input */
		for (; *value != '\0'; value++, input++) {
			if (*input != *value)
				return NULL;
		}
	}
	return str_c(output);
}

static unsigned int
test_imap_match_list(struct test_exec_context *ctx,
		     const struct imap_arg *match,
		     const struct imap_arg *args)
{
	bool unordered = FALSE;
	unsigned int chain_count = 1;
	const char *str;
	unsigned int i, j, arg_count, ret = 0;
	buffer_t *matchbuf;
	unsigned char *matches;
	ARRAY_DEFINE(ignores, const char *);
	ARRAY_DEFINE(bans, const char *);
	int noextra = -1;

	/* get $! directives */
	t_array_init(&ignores, 8);
	t_array_init(&bans, 8);
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
		} else if (strncmp(str, "ignore=", 7) == 0) {
			str += 7;
			array_append(&ignores, &str, 1);
		} else if (strncmp(str, "ban=", 4) == 0) {
			str += 4;
			array_append(&bans, &str, 1);
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
		return 0;
	}

	/* try to find each chain separately */
	matchbuf = buffer_create_dynamic(pool_datastack_create(), arg_count);
	matches = buffer_append_space_unsafe(matchbuf, arg_count);
	for (; match->type != IMAP_ARG_EOL; match += chain_count, ret++) {
		for (i = 0; i < arg_count; i += chain_count) {
			if (test_imap_match_args(ctx, match, &args[i],
						 chain_count, FALSE) == -1U) {
				matches[i] = 1;
				break;
			}
		}
		if (i == arg_count) {
			/* not found */
			return ret;
		}
	}
	if (noextra) {
		/* make sure everything got matched */
		const char *const *s;
		unsigned int i, count;

		for (i = 0; i < arg_count; i += chain_count) {
			if (matches[i] != 0)
				continue;

			if (!IMAP_ARG_TYPE_IS_STRING(args[i].type))
				return ret;

			/* is it in our ignore list? */
			s = array_get(&ignores, &count);
			for (j = 0; j < count; j++) {
				if (strcasecmp(s[j], args[i]._data.str) == 0)
					break;
			}
			if (j == count)
				return ret;
		}
	} else if (array_count(&bans) > 0) {
		const char *const *s;
		unsigned int i, count;

		for (i = 0; i < arg_count; i += chain_count) {
			if (matches[i] != 0)
				continue;

			if (!IMAP_ARG_TYPE_IS_STRING(args[i].type))
				continue;

			/* is it in our ban list? */
			s = array_get(&bans, &count);
			for (j = 0; j < count; j++) {
				if (strcasecmp(s[j], args[i]._data.str) == 0)
					break;
			}
			if (j != count)
				return ret;
		}
	}
	return -1U;
}

static unsigned int
test_imap_match_args(struct test_exec_context *ctx,
		     const struct imap_arg *match,
		     const struct imap_arg *args,
		     unsigned int max, bool prefix)
{
	const char *mstr, *astr;
	unsigned int subret, ret = 0;

	for (; match->type != IMAP_ARG_EOL && max > 0; match++, args++, max--) {
		switch (match->type) {
		case IMAP_ARG_NIL:
			if (args->type != IMAP_ARG_NIL)
				return ret;
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
				return ret;
			astr = IMAP_ARG_STR(args);
			mstr = test_expand_input(ctx, IMAP_ARG_STR(match),
						 astr);
			if (mstr == NULL)
				return ret;
			if (prefix && match[1].type == IMAP_ARG_EOL) {
				if (strncasecmp(astr, mstr, strlen(mstr)) != 0)
					return ret;
			} else {
				if (strcasecmp(astr, mstr) != 0)
					return ret;
			}
			break;
		case IMAP_ARG_LIST:
			if (args->type != IMAP_ARG_LIST)
				return ret;
			subret = test_imap_match_list(ctx,
						      IMAP_ARG_LIST_ARGS(match),
						      IMAP_ARG_LIST_ARGS(args));
			if (subret != -1U)
				return ret + subret;
			break;
		case IMAP_ARG_LITERAL_SIZE:
		case IMAP_ARG_LITERAL_SIZE_NONSYNC:
			i_panic("Match args contain literal size");
			break;
		case IMAP_ARG_EOL:
			i_unreached();
		}
		ret++;
	}
	if (prefix || args->type == IMAP_ARG_EOL || max == 0)
		return -1U;
	else
		return ret;
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
	const struct test_untagged *untagged;
	struct test_maybe_match *maybes;
	const char *const *vars;
	unsigned char *found;
	unsigned int i, count, j, var_count, match_count;
	bool prefix = FALSE, found_some;

	cmdp = array_idx(&ctx->test->commands, ctx->cur_cmd_idx);
	if (!array_is_created(&(*cmdp)->untagged)) {
		/* no untagged replies defined for the command.
		   don't bother checking further */
		return;
	}
	untagged = array_get(&(*cmdp)->untagged, &count);
	i_assert(count > 0);

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
	found = buffer_get_space_unsafe(ctx->cur_received_untagged, 0, count);
	(void)array_idx_modifiable(&ctx->cur_maybe_matches, count-1);
	maybes = array_idx_modifiable(&ctx->cur_maybe_matches, 0);
	found_some = FALSE;
	for (i = 0; i < count; i++) {
		if (found[i] != 0)
			continue;

		match_count = test_imap_match_args(ctx, untagged[i].args, args,
						   -1U, prefix);
		if (match_count == -1U) {
			if (untagged[i].not_found) {
				test_fail(ctx, "Unexpected untagged match:\n"
					  "Match: %s\n"
					  "Reply: %s",
					  imap_args_to_str(untagged[i].args),
					  imap_args_to_str(args));
				return;
			}
			found[i] = 1;
			/* continue - we may want to match more */
			found_some = TRUE;
			array_clear(&ctx->added_variables);
			continue;
		}
		if (maybes[i].count < match_count) {
			maybes[i].count = match_count;
			maybes[i].str =
				p_strdup(ctx->pool, imap_args_to_str(args));
		}

		/* if any variables were added, revert them */
		vars = array_get(&ctx->added_variables, &var_count);
		for (j = 0; j < var_count; j++)
			hash_remove(ctx->variables, vars[j]);
		array_clear(&ctx->added_variables);
	}
	if (!found_some)
		ctx->cur_untagged_mismatch_count++;
}

static int
test_handle_untagged(struct client *client, const struct imap_arg *args)
{
	struct test_exec_context *ctx = client->test_exec_ctx;

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
	if (args->type == IMAP_ARG_ATOM &&
	    args[1].type == IMAP_ARG_LIST &&
	    IMAP_ARG_TYPE_IS_STRING(args[2].type) &&
	    IMAP_ARG_TYPE_IS_STRING(args[3].type)) {
		const char *name = IMAP_ARG_STR(&args[3]);

		if (strcasecmp(args->_data.str, "list") == 0) {
			name = p_strdup(ctx->pool, name);
			array_append(&ctx->delete_mailboxes, &name, 1);
		} else if (strcasecmp(args->_data.str, "lsub") == 0) {
			name = p_strdup(ctx->pool, name);
			array_append(&ctx->unsubscribe_mailboxes, &name, 1);
		}
	}
	return 0;
}

static void test_cmd_callback(struct client *client,
			      struct command *command,
			      const struct imap_arg *args,
			      enum command_reply reply)
{
	struct test_exec_context *ctx = client->test_exec_ctx;
	struct test_command *const *cmdp;
	const struct test_command *cmd;
	const struct test_untagged *ut;
	const unsigned char *found;
	unsigned int i, first_missing_idx, missing_count, ut_count;

	i_assert(ctx->init_finished);
	i_assert(ctx->cur_cmd == command);

	if (reply == REPLY_CONT) {
		i_assert(command->state == STATE_APPEND);
		if (client_append_continue(client) < 0)
			test_fail(ctx, "APPEND failed");
		return;
	}
	client_handle_tagged_resp_text_code(client, command, args, reply);

	cmdp = array_idx(&ctx->test->commands, ctx->cur_cmd_idx);
	cmd = *cmdp;

	if (test_imap_match_args(ctx, cmd->reply, args, -1U, TRUE) != -1U) {
		test_fail(ctx, "Expected tagged reply '%s', got '%s'",
			  imap_args_to_str(cmd->reply),
			  imap_args_to_str(args));
	} else if (array_is_created(&cmd->untagged)) {
		ut = array_get(&cmd->untagged, &ut_count);
		first_missing_idx = ut_count;
		missing_count = 0;
		found = ctx->cur_received_untagged->data;
		for (i = 0; i < ut_count; i++) {
			if (!ut[i].not_found &&
			    (i >= ctx->cur_received_untagged->used ||
			     found[i] == 0)) {
				if (i < first_missing_idx)
					first_missing_idx = i;
				missing_count++;
			}
		}

		if (missing_count != 0) {
			const struct test_maybe_match *maybes;
			const char *best_match;
			unsigned int mcount;

			ut += first_missing_idx;
			maybes = array_get(&ctx->cur_maybe_matches, &mcount);
			best_match = mcount < first_missing_idx ? NULL :
				maybes[first_missing_idx].str;

			test_fail(ctx, "Missing %u untagged replies "
				  "(%u mismatches)\n"
				  " - first unexpanded: %s\n"
				  " - first expanded: %s\n"
				  " - best match: %s", missing_count,
				  ctx->cur_untagged_mismatch_count,
				  imap_args_to_str(ut->args),
				  test_expand_all(ctx, imap_args_to_str(ut->args), TRUE),
				  best_match == NULL ? "" : best_match);
		}
	}

	ctx->cur_cmd = NULL;
	ctx->cur_cmd_idx++;
	test_send_next_command(ctx);
}

static bool imap_arg_is_bad(const struct imap_arg *arg)
{
	if (!IMAP_ARG_TYPE_IS_STRING(arg->type))
		return FALSE;
	return strcasecmp(IMAP_ARG_STR_NONULL(arg), "bad") == 0;
}

static void test_send_next_command(struct test_exec_context *ctx)
{
	struct test_command *const *cmdp;
	struct client *client;
	const char *cmdline;
	uint32_t seq;

	i_assert(ctx->cur_cmd == NULL);

	if (ctx->cur_cmd_idx == array_count(&ctx->test->commands)) {
		test_execute_finish(ctx);
		return;
	}
	cmdp = array_idx(&ctx->test->commands, ctx->cur_cmd_idx);
	client = ctx->clients[(*cmdp)->connection_idx];

	ctx->cur_untagged_mismatch_count = 0;
	buffer_reset(ctx->cur_received_untagged);
	array_clear(&ctx->cur_maybe_matches);

	/* create initial sequence map */
	array_clear(&ctx->cur_seqmap);
	for (seq = 1; seq <= array_count(&client->view->uidmap); seq++)
		array_append(&ctx->cur_seqmap, &seq, 1);

	cmdline = test_expand_all(ctx, (*cmdp)->command, FALSE);
	if (strcasecmp(cmdline, "append") == 0) {
		client->state = STATE_APPEND;
		(void)client_append_full(client, NULL, NULL, NULL,
					 test_cmd_callback, &ctx->cur_cmd);
	} else if (strncasecmp(cmdline, "append ", 7) == 0) {
		client->state = STATE_APPEND;
		(void)client_append(client, cmdline + 7, FALSE,
				    test_cmd_callback, &ctx->cur_cmd);
	} else {
		client->state = STATE_SELECT;
		ctx->cur_cmd = command_send(client, cmdline, test_cmd_callback);
		if (imap_arg_is_bad((*cmdp)->reply))
			ctx->cur_cmd->expect_bad = TRUE;
	}
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

	ctx->init_finished = TRUE;
	test_send_next_command(ctx);
}

static void wakeup_clients(struct test_exec_context *ctx)
{
	unsigned int i;

	/* if any other clients were waiting on us, resume them */
	for (i = 1; i < ctx->test->connection_count; i++) {
		if (ctx->clients[i]->state == STATE_NOOP) {
			ctx->clients[i]->state = STATE_SELECT;
			test_send_lstate_commands(ctx->clients[i]);
		}
	}
}

static int rev_strcasecmp(const void *p1, const void *p2)
{
	const char *const *s1 = p1, *const *s2 = p2;

	return -strcasecmp(*s1, *s2);
}

static unsigned int
mailbox_foreach(struct client *client,
		ARRAY_TYPE(const_string) *mailboxes, const char *cmd)
{
	const char **boxes, *str;
	unsigned int i, count;

	boxes = array_get_modifiable(mailboxes, &count);
	qsort(boxes, count, sizeof(*boxes), rev_strcasecmp);
	for (i = 0; i < count; i++) {
		str = t_strdup_printf("%s %s", cmd, t_imap_quote_str(boxes[i]));
		command_send(client, str, init_callback);
	}
	array_clear(mailboxes);
	return count;
}

static void init_callback(struct client *client, struct command *command,
			  const struct imap_arg *args,
			  enum command_reply reply)
{
	struct test_exec_context *ctx = client->test_exec_ctx;

	i_assert(!ctx->init_finished);

	if (reply == REPLY_CONT) {
		i_assert(command->state == STATE_APPEND);
		if (client_append_continue(client) < 0)
			test_fail(ctx, "APPEND failed");
		return;
	}
	client_handle_tagged_resp_text_code(client, command, args, reply);

	/* Ignore if DELETE fails. It was probably a \NoSelect mailbox. */
	if (reply == REPLY_BAD ||
	    (reply == REPLY_NO &&
	     !(client->state == STATE_MDELETE && ctx->delete_refcount > 0))) {
		test_fail(ctx, "%s (tag %u.%u) failed: %s", command->cmdline,
			  client->global_id, command->tag,
			  imap_args_to_str(args));
		return;
	}
	if (ctx->listing) {
		if (array_count(&client->commands) > 0)
			return;
		/* both LSUB and LIST done */
		ctx->listing = FALSE;
		if (array_count(&ctx->delete_mailboxes) > 0 ||
		    array_count(&ctx->unsubscribe_mailboxes) > 0) {
			ctx->delete_refcount +=
				mailbox_foreach(client, &ctx->delete_mailboxes,
						"DELETE");
			ctx->delete_refcount +=
				mailbox_foreach(client,
						&ctx->unsubscribe_mailboxes,
						"UNSUBSCRIBE");
			return;
		}
		/* nothing to delete/unsubscribe */
	} else if (client->state == STATE_MDELETE && ctx->delete_refcount > 0) {
		if (--ctx->delete_refcount > 0)
			return;
	}

	if (ctx->startup_state == TEST_STARTUP_STATE_APPENDED) {
		/* waiting for all clients to finish SELECTing */
		i_assert(ctx->test->startup_state == TEST_STARTUP_STATE_SELECTED);
		if (--ctx->clients_waiting == 0) {
			ctx->startup_state++;
			test_send_first_command(ctx);
		} else if (client == ctx->clients[0])
			wakeup_clients(ctx);
	} else if (client->state != STATE_APPEND) {
		/* continue to next command */
		ctx->startup_state++;
	}
}

static int test_send_lstate_commands(struct client *client)
{
	struct test_exec_context *ctx = client->test_exec_ctx;
	struct command *cmd;
	const char *str, *mask;

	i_assert(ctx->clients_waiting > 0);

	if (ctx->failed)
		return -1;
	if (ctx->startup_state == ctx->test->startup_state &&
	    (client->login_state != LSTATE_NONAUTH ||
	     ctx->test->startup_state == TEST_STARTUP_STATE_NONAUTH)) {
		/* we're in the wanted state. selected state handling is
		   done in init_callback to make sure that all commands have
		   been finished before starting the test. */
		if (ctx->test->startup_state != TEST_STARTUP_STATE_SELECTED) {
			if (--ctx->clients_waiting == 0)
				test_send_first_command(ctx);
			else if (client == ctx->clients[0])
				wakeup_clients(ctx);
		}
		return 0;
	}

	client->plan_size = 0;
	switch (client->login_state) {
	case LSTATE_NONAUTH:
		client->plan[0] = STATE_LOGIN;
		client->plan_size = 1;
		if (client_plan_send_next_cmd(client) < 0)
			return -1;
		if (client == ctx->clients[0])
			ctx->startup_state = TEST_STARTUP_STATE_AUTH;
		break;
	case LSTATE_AUTH:
		/* the first client will delete and recreate the mailbox */
		if (client != ctx->clients[0] &&
		    ctx->startup_state != TEST_STARTUP_STATE_APPENDED) {
			/* wait until the mailbox is created */
			client->state = STATE_NOOP;
			break;
		}

		switch (ctx->startup_state) {
		case TEST_STARTUP_STATE_AUTH:
			if (ctx->delete_refcount > 0 || ctx->listing)
				return 0;

			mask = t_strconcat(client->view->storage->name,
					   "*", NULL);
			mask = t_imap_quote_str(mask);

			ctx->listing = TRUE;
			client->state = STATE_MDELETE;
			str = t_strdup_printf("LIST \"\" %s", mask);
			command_send(client, str, init_callback);
			str = t_strdup_printf("LSUB \"\" %s", mask);
			command_send(client, str, init_callback);
			break;
		case TEST_STARTUP_STATE_DELETED:
			client->state = STATE_MCREATE;
			str = t_strdup_printf("CREATE %s",
				t_imap_quote_str(client->view->storage->name));
			command_send(client, str, init_callback);
			break;
		case TEST_STARTUP_STATE_CREATED:
			if (ctx->appends_left > 0 &&
			    (!mailbox_source_eof(ctx->source) ||
			     ctx->test->message_count != -1U)) {
				client->state = STATE_APPEND;
				ctx->appends_left--;
				if (client_append_full(client, NULL, NULL, NULL,
						       init_callback, &cmd) < 0)
					return -1;
				break;
			}
			/* finished appending */
			ctx->startup_state++;
			return test_send_lstate_commands(client);
		case TEST_STARTUP_STATE_APPENDED:
			str = t_strdup_printf("SELECT %s",
				t_imap_quote_str(client->view->storage->name));
			client->state = STATE_SELECT;
			command_send(client, str, init_callback);
			break;
		case TEST_STARTUP_STATE_NONAUTH:
		case TEST_STARTUP_STATE_SELECTED:
			i_unreached();
		}
		break;
	case LSTATE_SELECTED:
		/* waiting for everyone to finish SELECTing */
		break;
	}
	return 0;
}

static int test_execute(const struct test *test,
			struct tests_execute_context *exec_ctx)
{
	struct test_exec_context *ctx;
	unsigned int i;
	pool_t pool;

	pool = pool_alloconly_create("test exec context", 2048);
	ctx = p_new(pool, struct test_exec_context, 1);
	ctx->pool = pool;
	ctx->test = test;
	ctx->exec_ctx = exec_ctx;
	ctx->source = mailbox_source_new(test->mbox_source_path);
	ctx->cur_received_untagged =
		buffer_create_dynamic(default_pool, 128);
	i_array_init(&ctx->cur_maybe_matches, 32);
	ctx->variables = hash_create(default_pool, pool, 0, str_hash,
				     (hash_cmp_callback_t *)strcmp);
	p_array_init(&ctx->added_variables, pool, 32);
	i_array_init(&ctx->cur_seqmap, 128);
	p_array_init(&ctx->delete_mailboxes, pool, 16);
	p_array_init(&ctx->unsubscribe_mailboxes, pool, 16);
	ctx->appends_left = ctx->test->message_count;

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
	ctx->startup_state = TEST_STARTUP_STATE_NONAUTH;
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
	array_free(&ctx->cur_maybe_matches);
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
