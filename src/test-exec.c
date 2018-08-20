/* Copyright (c) 2007-2018 ImapTest authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "hash.h"
#include "str.h"
#include "uri-util.h"
#include "imap-quote.h"
#include "imap-util.h"
#include "imap-arg.h"
#include "imap-utf7.h"
#include "mailbox.h"
#include "mailbox-source.h"
#include "imap-client.h"
#include "commands.h"
#include "settings.h"
#include "test-parser.h"
#include "test-exec.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>

#define IS_VAR_CHAR(c) (i_isalnum(c) || (c) == '_')

struct tests_execute_context {
	const ARRAY_TYPE(test) *tests;
	unsigned int next_test;
	unsigned int base_failures, base_tests;
	unsigned int ext_failures, ext_tests;
	unsigned int group_failures;
	unsigned int group_skips;
};

struct test_maybe_match {
	const char *str;
	unsigned int count;
};

struct test_exec_context {
	pool_t pool;

	struct tests_execute_context *exec_ctx;
	const struct test *test;

	/* current command group index */
	unsigned int cur_group_idx;
	unsigned int cur_untagged_mismatch_count;
	const char *first_extra_reply;
	ARRAY(struct command *) cur_commands;
	buffer_t *cur_received_untagged;
	ARRAY(struct test_maybe_match) cur_maybe_matches;
	/* initial sequence -> current sequence (0=expunged) mapping */
	ARRAY(uint32_t) cur_seqmap;

	struct imap_client **clients;
	struct mailbox_source *source;
	unsigned int clients_waiting, disconnects_waiting;
	unsigned int appends_left;

	ARRAY_TYPE(const_string) delete_mailboxes, unsubscribe_mailboxes;
	unsigned int delete_refcount;

	HASH_TABLE(const char *, const char *) variables;
	ARRAY(const char *) added_variables;

	enum test_startup_state startup_state;
	bool failed:1;
	bool skipped:1;
	bool finished:1;
	bool init_finished:1;
	bool listing:1;
};

static const char *tag_hash_key = "tag";

static void init_callback(struct imap_client *client, struct command *command,
			  const struct imap_arg *args,
			  enum command_reply reply);

static void test_execute_free(struct test_exec_context *ctx);
static void test_execute_finish(struct test_exec_context *ctx);
static void test_send_next_command_group(struct test_exec_context *ctx);
static int test_send_lstate_commands(struct client *client);

static unsigned int
test_imap_match_args(struct test_exec_context *ctx,
		     const struct imap_arg *match,
		     const struct imap_arg *args,
		     unsigned int max, bool prefix);

static const char *t_imap_quote_str(const char *src)
{
	string_t *dest = t_str_new(64);

	imap_append_string(dest, src);
	return str_c(dest);
}

static void ATTR_FORMAT(2, 3)
test_fail(struct test_exec_context *ctx, const char *fmt, ...)
{
	struct test_command_group *const *groupp;
	const struct test_command *cmd;
	struct imap_client *client;
	string_t *str;
	va_list args;

	groupp = array_idx(&ctx->test->cmd_groups, ctx->cur_group_idx);
	client = ctx->clients[(*groupp)->connection_idx];

	va_start(args, fmt);
	if (!ctx->init_finished) {
		fprintf(stderr, "*** Test %s initialization failed: %s\n",
			ctx->test->name, t_strdup_vprintf(fmt, args));
	} else {
		/* FIXME: we're now just showing the first command in the
		   group. the failing one might be something else, or the
		   group altogether.. */
		cmd = array_idx(&(*groupp)->commands, 0);
		str = t_str_new(256);
		str_printfa(str, "*** Test %s command %u/%u (line %u)\n - failed: %s\n"
			    " - Command", ctx->test->name, ctx->cur_group_idx+1,
			    array_count(&ctx->test->cmd_groups),
			    cmd->linenum, t_strdup_vprintf(fmt, args));
		if (cmd->cur_cmd_tag != 0 && client != NULL) {
			str_printfa(str, " (tag %u.%u)",
				    client->client.global_id, cmd->cur_cmd_tag);
		}
		str_printfa(str, ": %s", cmd->command);
		fprintf(stderr, "%s\n\n", str_c(str));
	}
	va_end(args);

	if (ctx->test->required_capabilities == NULL)
		ctx->exec_ctx->base_failures++;
	else
		ctx->exec_ctx->ext_failures++;
	ctx->failed = TRUE;
}

static struct test_command *
test_cmd_find_by_cur_tag(struct test_command_group *group,
			 unsigned int cur_cmd_tag)
{
	struct test_command *cmd;

	i_assert(cur_cmd_tag != 0);

	array_foreach_modifiable(&group->commands, cmd) {
		if (cmd->cur_cmd_tag == cur_cmd_tag)
			return cmd;
	}
	return NULL;
}

static bool test_group_have_pending_commands(struct test_command_group *group)
{
	const struct test_command *cmd;

	array_foreach(&group->commands, cmd) {
		if (cmd->cur_cmd_tag != 0)
			return TRUE;
	}
	return FALSE;
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

static void
test_expand_all(struct test_exec_context *ctx, const char **_line,
		unsigned int *_line_len, bool skip_uninitialized)
{
	const unsigned char *line = (const void *)*_line;
	unsigned int line_len = *_line_len;
	string_t *value;
	const unsigned char *p;
	const char *var_name, *var_value;
	uint32_t seq;

	p = memchr(line, '$', line_len);
	if (p == NULL)
		return;

	/* need to expand variables */
	value = t_str_new(256);
	buffer_append(value, line, p-line);
	line_len -= p-line;
	for (line = p; line_len > 0; ) {
		if (*line != '$' || line_len == 1) {
			str_append_c(value, *line);
			line++; line_len--;
			continue;
		}
		line++; line_len--;

		if (*line == '$') {
			str_append_c(value, *line);
			line++; line_len--;
		} else if (*line == '!') {
			/* skip directives */
			while (line[1] != ' ' && line_len > 1) {
				line++;
				line_len--;
			}
			line++; line_len--;
		} else {
			if (*line == '{') {
				line++; line_len--;
				p = memchr(line, '}', line_len);
				if (p == NULL) {
					test_fail(ctx, "Missing '}'");
					break;
				}
				var_name = t_strdup_until(line, p++);
			} else {
				for (p = line; IS_VAR_CHAR(*p); p++) ;
				var_name = t_strdup_until(line, p);
			}

			if (str_to_uint32(var_name, &seq) == 0) {
				/* relative sequence */
				var_value = test_expand_relative_seq(ctx, seq);
			} else {
				var_value = hash_table_lookup(ctx->variables,
							      var_name);
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
			line_len -= p-line;
			line = p;
		}
	}
	i_assert(*line == '\0' || ctx->failed);
	*_line = str_c(value);
	*_line_len = str_len(value);
}

static const char *
test_expand_input(struct test_exec_context *ctx, const char *str,
		  const char *input)
{
	const char *p, *ckey, *value, *var_name, *tmp_str;
	const char *key, *value2;
	string_t *output;
	uint32_t seq;

	output = t_str_new(128);
	for (; *str != '\0'; ) {
		if (*str != '$' || str[1] == '$') {
			if (str[0] == '$') str++;
			if (i_toupper(*str) != i_toupper(*input)) {
				/* mismatch already */
				return NULL;
			}
			input++;
			str_append_c(output, *str++);
			continue;
		}
		str++;

		if (*str == '{') {
			p = strchr(str + 1, '}');
			if (p == NULL)
				return "";
			var_name = t_strdup_until(str + 1, p);
			str = p + 1;
		} else {
			for (p = str; IS_VAR_CHAR(*p); p++) ;
			var_name = t_strdup_until(str, p);
			str = p;
		}

		if (str_to_uint32(var_name, &seq) == 0) {
			/* relative sequence */
			value = test_expand_relative_seq(ctx, seq);
		} else {
			value = var_name[0] == '\0' ? NULL :
				hash_table_lookup(ctx->variables, var_name);
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

				if (var_name[0] == '\0') {
					/* "$" just ignores the value */
					value = t_strdup_until(input, p);
				} else {
					key = p_strdup(ctx->pool, var_name);
					value2 = p_strdup_until(ctx->pool, input, p);
					hash_table_insert(ctx->variables, key, value2);

					ckey = key;
					value = value2;
					array_append(&ctx->added_variables, &ckey, 1);
				}
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
	ARRAY(const char *) ignores;
	ARRAY(const char *) bans;
	int noextra = -1;

	/* get $! directives */
	t_array_init(&ignores, 8);
	t_array_init(&bans, 8);
	for (; imap_arg_get_atom(match, &str); match++) {
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
		return test_imap_match_args(ctx, match, args, UINT_MAX, FALSE);
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
						 chain_count, FALSE) == UINT_MAX) {
				matches[i] = 1;
				break;
			}
		}
		if (i == arg_count) {
			/* not found */
			return ret;
		}
	}
	if (noextra > 0) {
		/* make sure everything got matched */
		const char *const *s;
		unsigned int i, count;

		for (i = 0; i < arg_count; i += chain_count) {
			if (matches[i] != 0)
				continue;

			if (!imap_arg_get_astring(&args[i], &str))
				continue;

			/* is it in our ignore list? */
			s = array_get(&ignores, &count);
			for (j = 0; j < count; j++) {
				if (strcasecmp(s[j], str) == 0)
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

			if (!imap_arg_get_astring(&args[i], &str))
				continue;

			/* is it in our ban list? */
			s = array_get(&bans, &count);
			for (j = 0; j < count; j++) {
				if (strcasecmp(s[j], str) == 0)
					break;
			}
			if (j != count)
				return ret;
		}
	}
	return UINT_MAX;
}

static unsigned int
test_imap_match_args(struct test_exec_context *ctx,
		     const struct imap_arg *match,
		     const struct imap_arg *args,
		     unsigned int max, bool prefix)
{
	const struct imap_arg *listargs;
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

			if (strcmp(imap_arg_as_astring(match), "$") == 0 &&
			    imap_arg_get_list(args, &listargs)) {
				/* "$" skips over a list */
				break;
			}
			if (!imap_arg_get_astring(args, &astr))
				return ret;
			mstr = test_expand_input(ctx, imap_arg_as_astring(match),
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
			if (!imap_arg_get_list(args, &listargs))
				return ret;
			subret = test_imap_match_list(ctx, imap_arg_as_list(match),
						      listargs);
			if (subret != UINT_MAX)
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
		return UINT_MAX;
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
test_handle_untagged_match(struct imap_client *client, const struct imap_arg *args)
{
	struct test_exec_context *ctx = client->test_exec_ctx;
	struct test_command_group *const *groupp;
	const struct test_command *cmd;
	const struct test_untagged *untagged;
	struct test_maybe_match *maybes;
	const char *const *vars, *tag, *str;
	unsigned char *found;
	unsigned int i, count, j, var_count, match_count;
	bool prefix = FALSE, found_some;

	groupp = array_idx(&ctx->test->cmd_groups, ctx->cur_group_idx);
	if (!array_is_created(&(*groupp)->untagged)) {
		if (ctx->test->ignore_extra_untagged ||
		    client->client.state == STATE_LOGOUT) {
			/* no untagged replies defined for the command and
			   we don't mind extra untagged replies.
			   don't bother checking further */
			return;
		}
		untagged = NULL;
		count = 0;
	} else {
		untagged = array_get(&(*groupp)->untagged, &count);
		i_assert(count > 0);
	}

	if (imap_arg_get_atom(args, &str)) {
		if (strcasecmp(str, "ok") == 0 ||
		    strcasecmp(str, "no") == 0 ||
		    strcasecmp(str, "bad") == 0 ||
		    strcasecmp(str, "bye") == 0) {
			/* these will have human-readable text appended after
			   [resp-text-code] */
			prefix = TRUE;
		}
	}

	cmd = array_idx(&(*groupp)->commands, 0);
	tag = cmd->cur_cmd_tag == 0 ? NULL :
		t_strdup_printf("%u.%u", client->client.global_id, cmd->cur_cmd_tag);
	array_clear(&ctx->added_variables);
	found = buffer_get_space_unsafe(ctx->cur_received_untagged, 0, count);
	if (count > 0)
		(void)array_idx_get_space(&ctx->cur_maybe_matches, count-1);
	maybes = array_idx_get_space(&ctx->cur_maybe_matches, 0);
	found_some = FALSE;
	for (i = 0; i < count; i++) {
		if (found[i] != 0)
			continue;

		if (tag != NULL)
			hash_table_insert(ctx->variables, tag_hash_key, tag);
		match_count = test_imap_match_args(ctx, untagged[i].args, args,
						   UINT_MAX, prefix);
		if (tag != NULL)
			hash_table_remove(ctx->variables, tag_hash_key);

		if (match_count == UINT_MAX) {
			if (untagged[i].existence == TEST_EXISTENCE_MUST_NOT_EXIST) {
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
			hash_table_remove(ctx->variables, vars[j]);
		array_clear(&ctx->added_variables);
	}
	if (!found_some) {
		ctx->cur_untagged_mismatch_count++;
		if (!ctx->test->ignore_extra_untagged &&
		    ctx->first_extra_reply == NULL)
			ctx->first_extra_reply = p_strdup(ctx->pool, imap_args_to_str(args));
	}
}

static int
test_handle_untagged(struct imap_client *client, const struct imap_arg *args)
{
	struct test_exec_context *ctx = client->test_exec_ctx;
	const char *str, *reply, *mailbox;

	if (imap_client_handle_untagged(client, args) < 0)
		return -1;

	if (ctx->init_finished)
		test_handle_untagged_match(client, args);

	if (imap_arg_get_atom(&args[0], &str) &&
	    imap_arg_atom_equals(&args[1], "EXPUNGE")) {
		/* expunge: update sequence mapping. do this after matching
		   expunges above. */
		uint32_t seq = strtoul(str, NULL, 10);

		test_handle_expunge(client->test_exec_ctx, seq);
	}
	if (imap_arg_get_atom(&args[0], &reply) &&
	    args[1].type == IMAP_ARG_LIST &&
	    IMAP_ARG_IS_NSTRING(&args[2]) &&
	    imap_arg_get_astring(&args[3], &mailbox)) {
		if (strcasecmp(reply, "list") == 0) {
			mailbox = p_strdup(ctx->pool, mailbox);
			array_append(&ctx->delete_mailboxes, &mailbox, 1);
		} else if (strcasecmp(reply, "lsub") == 0) {
			mailbox = p_strdup(ctx->pool, mailbox);
			array_append(&ctx->unsubscribe_mailboxes, &mailbox, 1);
		}
	}
	return 0;
}

static void
test_group_check_missing_untagged(struct test_exec_context *ctx,
				  struct test_command_group *group)
{
	const struct test_untagged *ut;
	const unsigned char *found;
	unsigned int i, first_missing_idx, missing_count, ut_count;

	ut = array_get(&group->untagged, &ut_count);
	first_missing_idx = ut_count;
	missing_count = 0;
	found = ctx->cur_received_untagged->data;
	for (i = 0; i < ut_count; i++) {
		if (ut[i].existence == TEST_EXISTENCE_MUST_EXIST &&
		    (i >= ctx->cur_received_untagged->used ||
		     found[i] == 0)) {
			if (i < first_missing_idx)
				first_missing_idx = i;
			missing_count++;
		}
	}

	if (missing_count != 0) {
		const struct test_maybe_match *maybes;
		const char *best_match, *str;
		unsigned int mcount, str_len;

		ut += first_missing_idx;
		maybes = array_get(&ctx->cur_maybe_matches, &mcount);
		best_match = mcount < first_missing_idx ? NULL :
			maybes[first_missing_idx].str;

		str = imap_args_to_str(ut->args);
		str_len = strlen(str);
		test_expand_all(ctx, &str, &str_len, TRUE);

		test_fail(ctx, "Missing %u untagged replies "
			  "(%u mismatches)\n"
			  " - first unexpanded: %s\n"
			  " - first expanded: %s\n"
			  " - best match: %s", missing_count,
			  ctx->cur_untagged_mismatch_count,
			  imap_args_to_str(ut->args), str,
			  best_match == NULL ? "" : best_match);
	}
}

static void test_group_output(struct test_exec_context *ctx,
			      struct test_command_group *group)
{
	const char *const *strp;

	array_foreach(&group->output, strp) T_BEGIN {
		const char *str = *strp;
		unsigned int str_len = strlen(str);

		test_expand_all(ctx, &str, &str_len, FALSE);
		printf("%s\n", str);
	} T_END;
}

static void test_group_finished(struct test_exec_context *ctx,
				struct test_command_group *group)
{
	if (array_is_created(&group->untagged))
		test_group_check_missing_untagged(ctx, group);

	if (ctx->first_extra_reply != NULL) {
		test_fail(ctx, "%u unexpected untagged replies received, first: %s",
			  ctx->cur_untagged_mismatch_count,
			  ctx->first_extra_reply);
	}
	if (array_is_created(&group->output))
		test_group_output(ctx, group);
	if (group->sleep_msecs > 0)
		usleep(group->sleep_msecs*1000);

	array_clear(&ctx->cur_commands);
	ctx->cur_group_idx++;
	if (ctx->test->required_capabilities == NULL)
		ctx->exec_ctx->base_tests++;
	else
		ctx->exec_ctx->ext_tests++;
	test_send_next_command_group(ctx);
}

static void test_cmd_callback(struct imap_client *client,
			      struct command *command,
			      const struct imap_arg *args,
			      enum command_reply reply)
{
	struct test_exec_context *ctx = client->test_exec_ctx;
	struct test_command_group *const *groupp;
	struct test_command *test_cmd;
	unsigned int match_count;
	const char *tag;

	i_assert(ctx->init_finished);

	if (reply == REPLY_CONT) {
		i_assert(command->state == STATE_APPEND);
		if (imap_client_append_continue(client) < 0)
			test_fail(ctx, "APPEND failed");
		return;
	}
	imap_client_handle_tagged_reply(client, command, args, reply);

	groupp = array_idx(&ctx->test->cmd_groups, ctx->cur_group_idx);
	test_cmd = test_cmd_find_by_cur_tag(*groupp, command->tag);

	tag = t_strdup_printf("%u.%u", client->client.global_id, command->tag);
	hash_table_insert(ctx->variables, tag_hash_key, tag);
	match_count = test_imap_match_args(ctx, test_cmd->reply,
					   args, UINT_MAX, TRUE);
	hash_table_remove(ctx->variables, tag_hash_key);

	if (match_count != UINT_MAX) {
		test_fail(ctx, "Expected tagged reply '%s', got '%s'",
			  imap_args_to_str(test_cmd->reply),
			  imap_args_to_str(args));
	}
	test_cmd->cur_cmd_tag = 0;

	if (!test_group_have_pending_commands(*groupp))
		test_group_finished(ctx, *groupp);
}

static bool imap_arg_is_bad(const struct imap_arg *arg)
{
	const char *str;

	if (!imap_arg_get_atom(arg, &str))
		return FALSE;
	return strcasecmp(str, "bad") == 0;
}

static bool
append_has_body(struct test_exec_context *ctx, const char *str_args,
		unsigned int str_args_len)
{
	ARRAY_TYPE(imap_arg_list) *arg_list;
	const struct imap_arg *args;
	const char *error;

	/* mailbox [(flags)] ["datetime"] */
	arg_list = test_parse_imap_args(ctx->pool, str_args, str_args_len,
					&error);
	if (arg_list == NULL)
		return FALSE;
	args = array_idx(arg_list, 0);
	if (args->type == IMAP_ARG_EOL)
		return FALSE;

	if (args[1].type == IMAP_ARG_LIST)
		args++;
	if (args[1].type == IMAP_ARG_STRING)
		args++;

	return args[1].type == IMAP_ARG_LITERAL ||
		args[1].type == IMAP_ARG_LITERAL_SIZE ||
		args[1].type == IMAP_ARG_LITERAL_SIZE_NONSYNC ||
		imap_arg_atom_equals(&args[1], "catenate");
}

static void test_send_next_command(struct test_exec_context *ctx,
				   struct imap_client *client,
				   struct test_command_group *group,
				   struct test_command *test_cmd)
{
	struct command *cmd = NULL;
	const char *cmdline;
	unsigned int cmdline_len;

	cmdline = test_cmd->command;
	cmdline_len = test_cmd->command_len;
	test_expand_all(ctx, &cmdline, &cmdline_len, FALSE);
	if (strcasecmp(cmdline, "append") == 0) {
		client->client.state = STATE_APPEND;
		(void)imap_client_append_full(client, NULL, NULL, NULL,
					      test_cmd_callback, &cmd);
	} else if (strncasecmp(cmdline, "append ", 7) == 0 &&
		   !append_has_body(ctx, cmdline+7, cmdline_len-7)) {
		client->client.state = STATE_APPEND;
		(void)imap_client_append(client, cmdline + 7, FALSE,
					 test_cmd_callback, &cmd);
	} else {
		if (test_cmd->linenum == 0 ||
		    strcasecmp(cmdline, "logout") == 0 ||
		    group->have_untagged_bye) {
			/* sending the logout command */
			client->client.state = STATE_LOGOUT;
			client->client.logout_sent = TRUE;
		} else {
			client->client.state = STATE_SELECT;
		}
		cmd = command_send_binary(client, cmdline, cmdline_len,
					  test_cmd_callback, NULL);
    if (imap_arg_is_bad(test_cmd->reply))
			cmd->expect_bad = TRUE;
	}
	test_cmd->cur_cmd_tag = cmd->tag;
	array_append(&ctx->cur_commands, &cmd, 1);
}

static void test_send_next_command_group(struct test_exec_context *ctx)
{
	struct test_command_group *const *groupp;
	struct test_command *cmd;
	struct imap_client *client;
	uint32_t seq;
	unsigned int i;

	i_assert(array_count(&ctx->cur_commands) == 0);

	if (ctx->cur_group_idx == array_count(&ctx->test->cmd_groups)) {
		test_execute_finish(ctx);
		return;
	}

	groupp = array_idx(&ctx->test->cmd_groups, ctx->cur_group_idx);
	client = ctx->clients[(*groupp)->connection_idx];

	ctx->first_extra_reply = NULL;
	ctx->cur_untagged_mismatch_count = 0;
	buffer_set_used_size(ctx->cur_received_untagged, 0);
	array_clear(&ctx->cur_maybe_matches);

	/* create initial sequence map */
	array_clear(&ctx->cur_seqmap);
	for (seq = 1; seq <= array_count(&client->view->uidmap); seq++)
		array_append(&ctx->cur_seqmap, &seq, 1);

	array_foreach_modifiable(&(*groupp)->commands, cmd)
		test_send_next_command(ctx, client, *groupp, cmd);

	/* if we're using multiple connections, stop reading input from the
	   other ones. otherwise if the server sends untagged events
	   immediately to us they'll get added to the current command's
	   untagged queue list, rather than the next command's on the
	   connection where they came from. */
	for (i = 0; i < ctx->test->connection_count; i++) {
		if (i == (*groupp)->connection_idx) {
			if (!ctx->clients[i]->client.disconnected)
				client_input_continue(&ctx->clients[i]->client);
		} else {
			client_input_stop(&ctx->clients[i]->client);
		}
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
		ctx->clients[i]->client.v.send_more_commands =
			test_send_no_commands;

	ctx->init_finished = TRUE;
	test_send_next_command_group(ctx);
}

static void wakeup_clients(struct test_exec_context *ctx)
{
	unsigned int i;

	/* if any other clients were waiting on us, resume them */
	for (i = 1; i < ctx->test->connection_count; i++) {
		if (ctx->clients[i]->client.state == STATE_NOOP) {
			ctx->clients[i]->client.state = STATE_SELECT;
			test_send_lstate_commands(&ctx->clients[i]->client);
		}
	}
}

static int rev_strcasecmp(const void *p1, const void *p2)
{
	const char *const *s1 = p1, *const *s2 = p2;

	return -strcasecmp(*s1, *s2);
}

static unsigned int
mailbox_foreach(struct imap_client *client,
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

static void init_callback(struct imap_client *client, struct command *command,
			  const struct imap_arg *args,
			  enum command_reply reply)
{
	struct test_exec_context *ctx = client->test_exec_ctx;

	i_assert(!ctx->init_finished);

	if (reply == REPLY_CONT) {
		i_assert(command->state == STATE_APPEND);
		if (imap_client_append_continue(client) < 0)
			test_fail(ctx, "APPEND failed");
		return;
	}
	imap_client_handle_tagged_reply(client, command, args, reply);

	/* Ignore if DELETE fails. It was probably a \NoSelect mailbox. */
	if (reply == REPLY_BAD ||
	    (reply == REPLY_NO &&
	     !(client->client.state == STATE_MDELETE && ctx->delete_refcount > 0))) {
		test_fail(ctx, "%s (tag %u.%u) failed: %s", command->cmdline,
			  client->client.global_id, command->tag,
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
	} else if (client->client.state == STATE_MDELETE && ctx->delete_refcount > 0) {
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
	} else if (client->client.state != STATE_APPEND) {
		/* continue to next command */
		ctx->startup_state++;
	}
}

static void
capability_callback(struct imap_client *client, struct command *command,
		    const struct imap_arg *args, enum command_reply reply)
{
	struct test_exec_context *ctx = client->test_exec_ctx;

	if (reply != REPLY_OK || !client->postlogin_capability)
		test_fail(ctx, "CAPABILITY failed");
	imap_client_handle_tagged_reply(client, command, args, reply);
}

static void
skip_logout_callback(struct imap_client *client ATTR_UNUSED,
		     struct command *command ATTR_UNUSED,
		     const struct imap_arg *args ATTR_UNUSED,
		     enum command_reply reply ATTR_UNUSED)
{
}

static void test_skip(struct test_exec_context *ctx)
{
	ctx->skipped = TRUE;
	/* Send LOGOUT to all connections and wait for their disconnection.
	   This way we don't exit while IMAP server is still in the middle of
	   processing some of the connections. */
	for (unsigned int i = 0; i < ctx->test->connection_count; i++) {
		ctx->clients[i]->client.state = STATE_LOGOUT;
		ctx->clients[i]->client.logout_sent = TRUE;
		ctx->disconnects_waiting++;
		command_send(ctx->clients[i], "LOGOUT",
			     skip_logout_callback);
	}
}

static bool test_have_all_capabilities(struct imap_client *client)
{
	struct test_exec_context *ctx = client->test_exec_ctx;
	const char *const *req = ctx->test->required_capabilities;
	char **have = client->capabilities_list;
	unsigned int i, j;

	if (ctx->test->require_user2 && conf.username2_template == NULL)
		return FALSE;

	if (req == NULL)
		return TRUE;

	for (i = 0; req[i] != NULL; i++) {
		for (j = 0; have[j] != NULL; j++) {
			if (strcasecmp(req[i], have[j]) == 0)
				break;
		}
		if (have[j] == NULL)
			return FALSE;
	}
	return TRUE;
}

static int test_send_lstate_commands(struct client *_client)
{
	struct imap_client *client = (struct imap_client *)_client;
	struct test_exec_context *ctx = client->test_exec_ctx;
	struct command *cmd;
	const char *str, *mask;

	i_assert(ctx->clients_waiting > 0);

	if (ctx->failed)
		return -1;
	if (ctx->startup_state == ctx->test->startup_state &&
	    (client->client.login_state != LSTATE_NONAUTH ||
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

	if (client->preauth && ctx->startup_state == TEST_STARTUP_STATE_NONAUTH)
		ctx->startup_state = TEST_STARTUP_STATE_AUTH;

	client->plan_size = 0;
	switch (client->client.login_state) {
	case LSTATE_NONAUTH:
		client->plan[0] = STATE_LOGIN;
		client->plan_size = 1;
		if (imap_client_plan_send_next_cmd(client) < 0)
			return -1;
		if (client == ctx->clients[0])
			ctx->startup_state = TEST_STARTUP_STATE_AUTH;
		break;
	case LSTATE_AUTH:
		/* the first client will delete and recreate the mailbox */
		if (client != ctx->clients[0] &&
		    ctx->startup_state != TEST_STARTUP_STATE_APPENDED) {
			/* wait until the mailbox is created */
			client->client.state = STATE_NOOP;
			break;
		}

		switch (ctx->startup_state) {
		case TEST_STARTUP_STATE_AUTH:
			if (ctx->delete_refcount > 0 || ctx->listing)
				return 0;

			if (!client->postlogin_capability) {
				command_send(client, "CAPABILITY",
					     capability_callback);
				return 0;
			} else if (!test_have_all_capabilities(client)) {
				test_skip(ctx);
				return 0;
			}
			mask = t_strconcat(client->storage->name, "*", NULL);
			mask = t_imap_quote_str(mask);

			ctx->listing = TRUE;
			client->client.state = STATE_MDELETE;
			str = t_strdup_printf("LIST \"\" %s", mask);
			command_send(client, str, init_callback);
			str = t_strdup_printf("LSUB \"\" %s", mask);
			command_send(client, str, init_callback);
			break;
		case TEST_STARTUP_STATE_DELETED:
			client->client.state = STATE_MCREATE;
			/* if we're testing with INBOX, don't try to
			   create it explicitly. it'll be autocreated, and
			   trying to create it may fail. */
			if (strcasecmp(client->storage->name, "INBOX") != 0) {
				str = t_strdup_printf("CREATE %s",
					t_imap_quote_str(client->storage->name));
				command_send(client, str, init_callback);
				break;
			}
			/* fall through */
		case TEST_STARTUP_STATE_CREATED:
			if (ctx->appends_left > 0 &&
			    (!mailbox_source_eof(ctx->source) ||
			     ctx->test->message_count != UINT_MAX)) {
				client->client.state = STATE_APPEND;
				ctx->appends_left--;
				if (imap_client_append_full(client, NULL, NULL, NULL,
							    init_callback, &cmd) < 0)
					return -1;
				break;
			}
			/* finished appending */
			ctx->startup_state++;
			return test_send_lstate_commands(_client);
		case TEST_STARTUP_STATE_APPENDED:
			str = t_strdup_printf("SELECT %s",
				t_imap_quote_str(client->storage->name));
			client->client.state = STATE_SELECT;
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

static const char *mailbox_mutf7_to_url(const char *mailbox)
{
	string_t *utf8val, *urlval;

	utf8val = t_str_new(256);
	if (imap_utf7_to_utf8(mailbox, utf8val) < 0)
		i_panic("Invalid mUTF-7 encoding for mailbox: %s", mailbox);

	urlval = t_str_new(256);
	uri_append_path_data(urlval, ";", str_c(utf8val));
	return str_c(urlval);
}

static bool test_exec_client_disconnected(struct client *_client)
{
	struct imap_client *client = (struct imap_client *)_client;
	struct test_exec_context *ctx = client->test_exec_ctx;
	struct test_command_group *const *groupp;
	const struct test_command *cmd;

	if (ctx->cur_group_idx == array_count(&ctx->test->cmd_groups))
		return TRUE;
	groupp = array_idx(&ctx->test->cmd_groups, ctx->cur_group_idx);
	if ((*groupp)->have_untagged_bye && client->seen_bye) {
		/* all commands must have "" as reply, or they'll fail */
		array_foreach(&(*groupp)->commands, cmd) {
			if (!imap_arg_atom_equals(&cmd->reply[0], "") ||
			    cmd->reply[1].type != IMAP_ARG_EOL) {
				test_fail(ctx, "Command expected '%s' as tagged reply - only \"\" allowed when BYE happens",
					  imap_args_to_str(cmd->reply));
			}
		}
		test_group_finished(ctx, *groupp);
		return FALSE;
	}
	return TRUE;
}

static int test_execute(const struct test *test,
			struct tests_execute_context *exec_ctx)
{
	struct test_exec_context *ctx;
	const struct test_connection *test_conns;
	unsigned int i, test_conn_count;
	const char *key, *value, *username;
	struct client *client;
	pool_t pool;

	users_free_all();

	pool = pool_alloconly_create("test exec context", 2048);
	ctx = p_new(pool, struct test_exec_context, 1);
	ctx->pool = pool;
	ctx->test = test;
	ctx->exec_ctx = exec_ctx;
	ctx->source = mailbox_source_new_mbox(test->mbox_source_path);
	ctx->cur_received_untagged =
		buffer_create_dynamic(default_pool, 128);
	p_array_init(&ctx->cur_commands, pool, 16);
	i_array_init(&ctx->cur_maybe_matches, 32);
	hash_table_create(&ctx->variables, pool, 0, str_hash, strcmp);
	p_array_init(&ctx->added_variables, pool, 32);
	i_array_init(&ctx->cur_seqmap, 128);
	p_array_init(&ctx->delete_mailboxes, pool, 16);
	p_array_init(&ctx->unsubscribe_mailboxes, pool, 16);
	ctx->appends_left = ctx->test->message_count;

	/* create clients for the test */
	test_conns = array_get(&test->connections, &test_conn_count);
	ctx->clients = p_new(pool, struct imap_client *, test->connection_count);
	for (i = 0; i < test->connection_count; i++) {
		username = NULL;
		if (i < test_conn_count)
			username = test_conns[i].username;
		if (username != NULL) {
			client = client_new_user(user_get(username, ctx->source));
		} else {
			client = client_new_random(array_count(&clients), ctx->source);
		}
		i_assert(client != NULL);
		i_assert(client->v.disconnected == NULL);
		client->v.disconnected = test_exec_client_disconnected;
		ctx->clients[i] = imap_client(client);
		i_assert(ctx->clients[i] != NULL);
		if (ctx->clients[i] == NULL) {
			test_execute_free(ctx);
			return -1;
		}
		ctx->clients[i]->handle_untagged = test_handle_untagged;
		ctx->clients[i]->client.v.send_more_commands =
			test_send_lstate_commands;
		ctx->clients[i]->test_exec_ctx = ctx;

		key = i == 0 ? "user" : p_strdup_printf(pool, "user%u", i+1);
		value = p_strdup(pool, ctx->clients[i]->client.user->username);
		hash_table_insert(ctx->variables, key, value);

		key = i == 0 ? "username" :
			p_strdup_printf(pool, "username%u", i+1);
		value = p_strdup(pool, t_strcut(ctx->clients[i]->client.user->username, '@'));
		hash_table_insert(ctx->variables, key, value);

		key = i == 0 ? "domain" :
			p_strdup_printf(pool, "domain%u", i+1);
		value = strchr(ctx->clients[i]->client.user->username, '@');
		if (value != NULL)
			value++;
		else
			value = p_strdup(pool, conf.host);
		hash_table_insert(ctx->variables, key, value);

		key = i == 0 ? "password" : p_strdup_printf(pool, "password%u", i+1);
		value = p_strdup(pool, ctx->clients[i]->client.user->password);
		hash_table_insert(ctx->variables, key, value);
	}
	ctx->startup_state = TEST_STARTUP_STATE_NONAUTH;
	ctx->clients_waiting = test->connection_count;

	key = "mailbox";
	value = p_strdup(pool, ctx->clients[0]->storage->name);
	hash_table_insert(ctx->variables, key, value);

	key = "mailbox_url";
	value = p_strdup(pool, mailbox_mutf7_to_url(value));
	hash_table_insert(ctx->variables, key, value);

	return 0;
}

static void tests_execute_next(struct tests_execute_context *exec_ctx)
{
	struct test *const *tests;
	unsigned int count;

	tests = array_get(exec_ctx->tests, &count);
	if (exec_ctx->next_test != count)
		test_execute(tests[exec_ctx->next_test++], exec_ctx);
	else {
		printf("%u test groups: %u failed, %u skipped due to missing capabilities\n",
		       count, exec_ctx->group_failures, exec_ctx->group_skips);
		printf("base protocol: %u/%u individual commands failed\n",
		       exec_ctx->base_failures, exec_ctx->base_tests);
		printf("extensions: %u/%u individual commands failed\n",
		       exec_ctx->ext_failures, exec_ctx->ext_tests);
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
	bool ret = ctx->group_failures == 0;

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
		ctx->exec_ctx->group_failures++;
	else if (ctx->skipped)
		ctx->exec_ctx->group_skips++;

	/* disconnect all clients */
	for (i = 0; i < ctx->test->connection_count; i++) {
		if (ctx->clients[i] != NULL)
			client_disconnect(&ctx->clients[i]->client);
	}
	ctx->disconnects_waiting = ctx->test->connection_count;
}

static void test_execute_free(struct test_exec_context *ctx)
{
	array_free(&ctx->cur_seqmap);
	hash_table_destroy(&ctx->variables);
	mailbox_source_unref(&ctx->source);
	buffer_free(&ctx->cur_received_untagged);
	array_free(&ctx->cur_maybe_matches);
	pool_unref(&ctx->pool);
}

static bool test_execute_is_cur_group_with_bye(struct test_exec_context *ctx)
{
	struct test_command_group *const *groupp;

	if (ctx->cur_group_idx == array_count(&ctx->test->cmd_groups))
		return FALSE;
	groupp = array_idx(&ctx->test->cmd_groups, ctx->cur_group_idx);
	return (*groupp)->have_untagged_bye;
}

void test_execute_cancel_by_client(struct imap_client *client)
{
	struct test_exec_context *ctx = client->test_exec_ctx;
	struct tests_execute_context *exec_ctx = ctx->exec_ctx;
	unsigned int i;

	for (i = 0; i < ctx->test->connection_count; i++) {
		if (ctx->clients[i] == client)
			ctx->clients[i] = NULL;
	}

	if (ctx->disconnects_waiting == 0) {
		if (!client->seen_bye ||
		    !test_execute_is_cur_group_with_bye(ctx))
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
