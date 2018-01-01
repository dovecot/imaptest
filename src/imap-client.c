/* Copyright (c) 2007-2018 ImapTest authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "write-full.h"
#include "istream.h"
#include "ostream.h"
#include "imap-seqset.h"
#include "imap-arg.h"
#include "imap-parser.h"
#include "imap-util.h"

#include "commands.h"
#include "settings.h"
#include "search.h"
#include "mailbox.h"
#include "mailbox-state.h"
#include "checkpoint.h"
#include "profile.h"
#include "test-exec.h"
#include "imap-client.h"

#include <stdlib.h>
#include <unistd.h>

int imap_client_input_error(struct imap_client *client, const char *fmt, ...)
{
	va_list va;

	va_start(va, fmt);
	i_error("%s[%u]: %s: %s", client->client.user->username,
		client->client.global_id,
		t_strdup_vprintf(fmt, va), client->cur_args == NULL ? "" :
		imap_args_to_str(client->cur_args));
	va_end(va);

	client_disconnect(&client->client);
	if (conf.error_quit)
		exit(2);
	return -1;
}

int imap_client_input_warn(struct imap_client *client, const char *fmt, ...)
{
	va_list va;

	va_start(va, fmt);
	i_error("%s[%u]: %s: %s", client->client.user->username,
		client->client.global_id,
		t_strdup_vprintf(fmt, va), client->cur_args == NULL ? "" :
		imap_args_to_str(client->cur_args));
	va_end(va);
	return -1;
}

int imap_client_state_error(struct imap_client *client, const char *fmt, ...)
{
	va_list va;

	va_start(va, fmt);
	i_error("%s[%u]: %s: %s", client->client.user->username,
		client->client.global_id,
		t_strdup_vprintf(fmt, va), client->cur_args == NULL ? "" :
		imap_args_to_str(client->cur_args));
	va_end(va);

	if (conf.error_quit)
		exit(2);
	return -1;
}

void imap_client_exists(struct imap_client *client, unsigned int msgs)
{
	unsigned int old_count = array_count(&client->view->uidmap);

	if (msgs < old_count) {
		imap_client_input_error(client, "Message count dropped %u -> %u",
					old_count, msgs);
		array_delete(&client->view->uidmap, msgs, old_count - msgs);
		return;
	}
	for (; old_count < msgs; old_count++)
		(void)array_append_space(&client->view->uidmap);
}

static int imap_client_expunge(struct imap_client *client, unsigned int seq)
{
	struct message_metadata_dynamic *metadata;
	unsigned int count = array_count(&client->view->uidmap);

	if (seq == 0) {
		imap_client_input_error(client, "Tried to expunge sequence 0");
		return -1;
	}
	if (seq > count) {
		imap_client_input_error(client,
			"Tried to expunge sequence %u with only %u msgs",
			seq, count);
		return -1;
	}

	metadata = array_idx_modifiable(&client->view->messages, seq - 1);
	if (metadata->fetch_refcount > 0) {
		imap_client_input_error(client,
			"Referenced message expunged seq=%u uid=%u",
			seq, metadata->ms == NULL ? 0 : metadata->ms->uid);
		return -1;
	}
	mailbox_view_expunge(client->view, seq);
	return 0;
}

static int imap_client_expunge_uid(struct imap_client *client, uint32_t uid)
{
	const uint32_t *uidmap;
	unsigned int i, count;

	/* if there are unknown UIDs we don't really know which one of them
	   we should expunge, but it doesn't matter because they contain no
	   metadata at that point. */
	uidmap = array_get(&client->view->uidmap, &count);
	for (i = 0; i < count; i++) {
		if (uid <= uidmap[i]) {
			if (uid == uidmap[i]) {
				/* found it */
				imap_client_expunge(client, i + 1);
				return 0;
			}
			break;
		}
	}

	/* there are one or more unknown messages. expunge the last one of them
	   (none of them should have any attached metadata) */
	if (i == 0 || uidmap[i-1] != 0) {
		imap_client_input_error(client, "VANISHED UID=%u not found", uid);
		return -1;
	}

	imap_client_expunge(client, i);
	return 0;
}

static void
imap_client_expunge_uid_range(struct imap_client *client,
			      const ARRAY_TYPE(seq_range) *expunged_uids)
{
	const uint32_t *uidmap;
	unsigned int seq, uid_count;

	uidmap = array_get(&client->view->uidmap, &uid_count);
	for (seq = uid_count; seq > 0; seq--) {
		i_assert(uidmap[seq-1] != 0);

		if (seq_range_exists(expunged_uids, uidmap[seq-1])) {
			imap_client_expunge(client, seq);
			uidmap = array_get(&client->view->uidmap, &uid_count);
		}
	}
}

static void
imap_client_enabled(struct imap_client *client, const struct imap_arg *args)
{
	const char *str;

	for (; imap_arg_get_atom(args, &str); args++) {
		if (strcasecmp(str, "QRESYNC") == 0)
			client->qresync_enabled = TRUE;
	}
}

static int client_vanished(struct imap_client *client, const struct imap_arg *args)
{
	struct mailbox_view *view = client->view;
	const struct imap_arg *subargs;
	ARRAY_TYPE(seq_range) uids;
	const struct seq_range *range;
	unsigned int i, count;
	const char *uidset;
	uint32_t uid;

	if (!client->qresync_enabled) {
		imap_client_input_error(client,
			"Server sent VANISHED but we hadn't enabled QRESYNC");
		return -1;
	}

	if (imap_arg_get_list(args, &subargs)) {
		if (imap_arg_atom_equals(&subargs[0], "EARLIER") &&
		    IMAP_ARG_IS_EOL(&subargs[1])) {
			if (client->qresync_select_cache == NULL) {
				/* we don't care */
				return 0;
			}
			/* SELECTing with QRESYNC */
			args++;
		}
	}

	if (!imap_arg_get_atom(&args[0], &uidset) ||
	    !IMAP_ARG_IS_EOL(&args[1])) {
		imap_client_input_error(client, "Invalid VANISHED parameters");
		return -1;
	}

	t_array_init(&uids, 16);
	if (imap_seq_set_parse(uidset, &uids) < 0) {
		imap_client_input_error(client, "Invalid VANISHED sequence-set");
		return -1;
	}

	if (view->known_uid_count == array_count(&view->uidmap)) {
		/* all UIDs are known - we can handle UIDs that are already
		   expunged. this happens normally when doing a SELECT QRESYNC
		   and server couldn't keep track of only the new expunges. */
		imap_client_expunge_uid_range(client, &uids);
		return 0;
	}

	/* we assume that there are no extra UIDs in the reply, even though
	   it's only a SHOULD in the spec. way too difficult to handle
	   otherwise. */
	range = array_get(&uids, &count);
	for (i = 0; i < count; i++) {
		for (uid = range[i].seq1; uid <= range[i].seq2; uid++)
			imap_client_expunge_uid(client, uid);
	}
	return 0;
}

static void
imap_client_list_result(struct imap_client *client, const struct imap_arg *args)
{
	struct mailbox_list_entry *list;
	const char *name;

	if (args[0].type != IMAP_ARG_LIST ||
	    !IMAP_ARG_IS_NSTRING(&args[1]) ||
	    !imap_arg_get_astring(&args[2], &name))
		return;

	if (!array_is_created(&client->mailboxes_list))
		i_array_init(&client->mailboxes_list, 4);

	/* don't add duplicates */
	array_foreach_modifiable(&client->mailboxes_list, list) {
		if (strcmp(list->name, name) == 0) {
			list->found = TRUE;
			return;
		}
	}
	list = array_append_space(&client->mailboxes_list);
	list->name = i_strdup(name);
	list->found = TRUE;
}

void imap_client_mailboxes_list_begin(struct imap_client *client)
{
	struct mailbox_list_entry *list;

	if (!array_is_created(&client->mailboxes_list))
		return;
	array_foreach_modifiable(&client->mailboxes_list, list)
		list->found = FALSE;
}

void imap_client_mailboxes_list_end(struct imap_client *client)
{
	struct mailbox_list_entry *lists;
	unsigned int i, count;

	lists = array_get_modifiable(&client->mailboxes_list, &count);
	for (i = count; i > 0; i--) {
		if (!lists[i-1].found) {
			i_free(lists[i-1].name);
			array_delete(&client->mailboxes_list, i-1, 1);
		}
	}
}

void imap_client_log_mailbox_view(struct imap_client *client)
{
	const struct message_metadata_dynamic *metadata;
	const uint32_t *uidmap;
	unsigned int i, count, metadata_count;
	string_t *str;

	if (client->client.rawlog_fd == -1)
		return;
	(void)o_stream_flush(client->client.output);

	str = t_str_new(256);
	str_printfa(str, "** view: highest_modseq=%llu\r\n",
		    (unsigned long long)client->view->highest_modseq);
	write_full(client->client.rawlog_fd, str_data(str), str_len(str));

	uidmap = array_get(&client->view->uidmap, &count);
	metadata = array_get(&client->view->messages, &metadata_count);
	i_assert(metadata_count == count);

	for (i = 0; i < count; i++) {
		str_truncate(str, 0);
		str_printfa(str, "seq=%u uid=%u modseq=%llu flags=(",
			    i+1, uidmap[i],
			    (unsigned long long)metadata[i].modseq);
		imap_write_flags(str, metadata[i].mail_flags, NULL);
		str_append(str, ") keywords=(");
		mailbox_view_keywords_write(client->view,
					    metadata[i].keyword_bitmask, str);
		str_append(str, ")\r\n");
		write_full(client->client.rawlog_fd, str_data(str), str_len(str));
	}
	write_full(client->client.rawlog_fd, "**\r\n", 4);
}

void imap_client_mailbox_close(struct imap_client *client)
{
	if (client->client.login_state == LSTATE_SELECTED && conf.qresync) {
		if (rand() % 3 == 0) {
			if (mailbox_view_save_offline_cache(client->view))
				imap_client_log_mailbox_view(client);
		}

		client->client.login_state = LSTATE_AUTH;
	}
	mailbox_view_free(&client->view);
	client->view = mailbox_view_new(client->storage);
}

struct mailbox_list_entry *
imap_client_mailboxes_list_find(struct imap_client *client, const char *name)
{
	struct mailbox_list_entry *list;

	array_foreach_modifiable(&client->mailboxes_list, list) {
		if (strcmp(list->name, name) == 0)
			return list;
	}
	return NULL;
}

void imap_client_capability_parse(struct imap_client *client, const char *line)
{
	const char *const *tmp;
	unsigned int i;

	if (client->client.login_state != LSTATE_NONAUTH)
		client->postlogin_capability = TRUE;

	client->capabilities = 0;
	if (client->capabilities_list != NULL)
		p_strsplit_free(default_pool, client->capabilities_list);
	client->capabilities_list = p_strsplit(default_pool, line, " ");

	for (tmp = t_strsplit(line, " "); *tmp != NULL; tmp++) {
		for (i = 0; cap_names[i].name != NULL; i++) {
			if (strcasecmp(*tmp, cap_names[i].name) == 0) {
				client->capabilities |= cap_names[i].capability;
				break;
			}
		}
	}
}

int imap_client_handle_untagged(struct imap_client *client,
				const struct imap_arg *args)
{
	struct mailbox_view *view = client->view;
	const char *str;
	unsigned int num;

	if (!imap_arg_get_atom(args, &str))
		return -1;
	str = t_str_ucase(str);
	args++;

	if (str_to_uint(str, &num) == 0) {
		if (!imap_arg_get_atom(args, &str))
			return -1;
		str = t_str_ucase(str);
		args++;

		if (strcmp(str, "EXISTS") == 0)
			imap_client_exists(client, num);

                if (num > array_count(&view->uidmap) &&
		    client->last_cmd->state > STATE_SELECT) {
			imap_client_input_warn(client,
				"seq too high (%u > %u, state=%s)",
				num, array_count(&view->uidmap),
                                states[client->last_cmd->state].name);
		} else if (strcmp(str, "EXPUNGE") == 0) {
			if (imap_client_expunge(client, num) < 0)
				return -1;
		} else if (strcmp(str, "RECENT") == 0) {
			view->recent_count = num;
			if (view->recent_count ==
			    array_count(&view->uidmap))
				view->storage->seen_all_recent = TRUE;
		} else if (!conf.no_tracking && strcmp(str, "FETCH") == 0)
			mailbox_state_handle_fetch(client, num, args);
	} else if (strcmp(str, "BYE") == 0) {
		if (!client->client.logout_sent || client->seen_bye)
			imap_client_input_warn(client, "Unexpected BYE");
		else
			counters[STATE_LOGOUT]++;
		imap_client_mailbox_close(client);
		client->seen_bye = TRUE;
		client->client.login_state = LSTATE_NONAUTH;
	} else if (strcmp(str, "FLAGS") == 0) {
		if (mailbox_state_set_flags(view, args) < 0)
			imap_client_input_error(client, "Broken FLAGS");
	} else if (strcmp(str, "CAPABILITY") == 0)
		imap_client_capability_parse(client, imap_args_to_str(args));
	else if (strcmp(str, "SEARCH") == 0)
		search_result(client, args);
	else if (strcmp(str, "LIST") == 0)
		imap_client_list_result(client, args);
	else if (strcmp(str, "ENABLED") == 0)
		imap_client_enabled(client, args);
	else if (strcmp(str, "VANISHED") == 0) {
		if (client_vanished(client, args) < 0)
			return -1;
	} else if (strcmp(str, "THREAD") == 0) {
		i_free(view->last_thread_reply);
		view->last_thread_reply = IMAP_ARG_IS_EOL(args) ?
			i_strdup("") :
			i_strdup(imap_args_to_str(args + 1));
	} else if (strcmp(str, "OK") == 0) {
		imap_client_handle_resp_text_code(client, args);
	} else if (strcmp(str, "NO") == 0) {
		/*i_info("%s: %s", client->user->username, line + 2);*/
	} else if (strcmp(str, "BAD") == 0) {
		imap_client_input_warn(client, "BAD received");
	}
	return 0;
}

static int
imap_client_input_args(struct imap_client *client, const struct imap_arg *args)
{
	const char *p, *tag, *tag_status;
	struct command *cmd;
	enum command_reply reply;

	if (!imap_arg_get_atom(args, &tag))
		return imap_client_input_error(client, "Broken tag");
	args++;

	if (strcmp(tag, "+") == 0) {
		if (client->last_cmd == NULL) {
			return imap_client_input_error(client,
				"Unexpected command continuation");
		}
		client->last_cmd->callback(client, client->last_cmd,
					   args, REPLY_CONT);
		return 0;
	}
	if (strcmp(tag, "*") == 0) {
		if (client->handle_untagged(client, args) < 0) {
			return imap_client_input_error(client,
						       "Invalid untagged input");
		}
		return 0;
	}

	/* tagged reply */
	if (!imap_arg_get_atom(args, &tag_status))
		return imap_client_input_error(client, "Broken tagged reply");

	p = strchr(tag, '.');
	cmd = p != NULL &&
		atoi(t_strdup_until(tag, p)) == (int)client->client.global_id ?
		command_lookup(client, atoi(t_strcut(p+1, ' '))) : NULL;
	if (cmd == NULL) {
		return imap_client_input_error(client,
			"Unexpected tagged reply: %s", tag);
	}

	if (strcasecmp(tag_status, "OK") == 0)
		reply = REPLY_OK;
	else if (strcasecmp(tag_status, "NO") == 0)
		reply = REPLY_NO;
	else if (strcasecmp(tag_status, "BAD") == 0) {
		reply = REPLY_BAD;
		if (!cmd->expect_bad) {
			imap_client_input_error(client, "BAD reply for command: %s",
						cmd->cmdline);
		}
	} else {
		return imap_client_input_error(client, "Broken tagged reply");
	}

	command_unlink(client, cmd);

	o_stream_cork(client->client.output);
	cmd->callback(client, cmd, args, reply);
	imap_client_cmd_reply_finish(client);
	o_stream_uncork(client->client.output);
	command_free(cmd);
	return 0;
}

static bool imap_client_skip_literal(struct imap_client *client)
{
	size_t size;

	if (client->literal_left == 0)
		return TRUE;

	(void)i_stream_get_data(client->client.input, &size);
	if (size < client->literal_left) {
		client->literal_left -= size;
		i_stream_skip(client->client.input, size);
		return FALSE;
	} else {
		i_stream_skip(client->client.input, client->literal_left);
		client->literal_left = 0;
		return TRUE;
	}
}

static void imap_client_input(struct client *_client)
{
	struct imap_client *client = (struct imap_client *)_client;
	const struct imap_arg *imap_args;
	const char *line, *p;
	uoff_t literal_size;
	const unsigned char *data;
	size_t size;
	bool fatal;
	int ret;

	if (!client->seen_banner) {
		/* we haven't received the banner yet */
		line = i_stream_next_line(_client->input);
		if (line == NULL)
			return;
		client->seen_banner = TRUE;

		if (strncasecmp(line, "* PREAUTH ", 10) == 0) {
			client->preauth = TRUE;
			_client->login_state = LSTATE_AUTH;
		} else if (strncasecmp(line, "* OK ", 5) != 0) {
			imap_client_input_error(client,
				"Malformed banner \"%s\"", line);
		}
		p = strstr(line, "[CAPABILITY ");
		if (p == NULL)
			command_send(client, "CAPABILITY", state_callback);
		else {
			imap_client_capability_parse(client, t_strcut(p + 12, ']'));
			(void)client_send_more_commands(_client);
		}
	}

	while (imap_client_skip_literal(client)) {
		ret = imap_parser_read_args(client->parser, 0,
					    IMAP_PARSE_FLAG_LITERAL_SIZE |
					    IMAP_PARSE_FLAG_LITERAL8 |
					    IMAP_PARSE_FLAG_ATOM_ALLCHARS,
					    &imap_args);
		if (ret == -2) {
			/* need more data */
			break;
		}
		if (ret < 0) {
			/* some error */
			imap_client_input_error(client,
				"error parsing input: %s",
				imap_parser_get_error(client->parser, &fatal));
			return;
		}
		if (imap_args->type == IMAP_ARG_EOL) {
			/* FIXME: we get here, but we shouldn't.. */
		} else {
			if (imap_parser_get_literal_size(client->parser,
							 &literal_size)) {
				if (literal_size <= MAX_INLINE_LITERAL_SIZE) {
					/* read the literal */
					imap_parser_read_last_literal(
						client->parser);
					continue;
				}
				/* literal too large. we still have to skip it
				   though. */
				client->literal_left = literal_size;
				continue;
			}

			/* FIXME: we should call this for large
			   literals too.. */
			client->cur_args = imap_args;
			T_BEGIN {
				ret = imap_client_input_args(client, imap_args);
			} T_END;
			client->cur_args = NULL;
		}

		if (client->literal_left == 0) {
			/* end of command - skip CRLF */
			imap_parser_reset(client->parser);

			data = i_stream_get_data(_client->input, &size);
			if (size > 0 && data[0] == '\r') {
				i_stream_skip(_client->input, 1);
				data = i_stream_get_data(_client->input, &size);
			}
			if (size > 0 && data[0] == '\n')
				i_stream_skip(_client->input, 1);
		}

		if (ret < 0)
			return;
	}
}

static int imap_client_output(struct client *_client)
{
	struct imap_client *client = (struct imap_client *)_client;

	if (client->append_stream != NULL && client->append_can_send) {
		if (imap_client_append_continue(client) < 0)
			return -1;
	}
	return 0;
}

static void imap_client_connected(struct client *_client)
{
	struct imap_client *client = (struct imap_client *)_client;

	client->parser = imap_parser_create(_client->input, NULL, (size_t)-1);
}

static void imap_client_logout(struct client *_client)
{
	struct imap_client *client = (struct imap_client *)_client;

	command_send(client, "LOGOUT", state_callback);
}

static void imap_client_free(struct client *_client)
{
	struct imap_client *client = (struct imap_client *)_client;
	struct mailbox_storage *storage = client->storage;
	struct mailbox_list_entry *list;
	struct command *const *cmds;
	unsigned int i, count;
	bool checkpoint;

	if (conf.disconnect_quit && _client->login_state != LSTATE_NONAUTH)
		exit(1);
	cmds = array_get(&client->commands, &count);
	checkpoint = client->checkpointing != NULL && count > 0;

	imap_client_mailbox_close(client);
	mailbox_view_free(&client->view);

	for (i = 0; i < count; i++)
		command_free(cmds[i]);
	array_free(&client->commands);

	if (client->qresync_select_cache != NULL)
		mailbox_offline_cache_unref(&client->qresync_select_cache);
	if (client->test_exec_ctx != NULL) {
		/* storage must be fully unreferenced before new test can
		   begin. */
		mailbox_storage_unref(&storage);
		test_execute_cancel_by_client(client);
	}
	if (client->parser != NULL)
		imap_parser_unref(&client->parser);
	if (client->append_stream != NULL)
		i_stream_unref(&client->append_stream);

	if (client->capabilities_list != NULL)
		p_strsplit_free(default_pool, client->capabilities_list);
	if (array_is_created(&client->mailboxes_list)) {
		array_foreach_modifiable(&client->mailboxes_list, list)
			i_free(list->name);
		array_free(&client->mailboxes_list);
	}
	if (storage != NULL) {
		if (checkpoint)
			checkpoint_neg(storage);
		mailbox_storage_unref(&storage);
	}
}

static const struct client_vfuncs imap_client_vfuncs = {
	.input = imap_client_input,
	.output = imap_client_output,
	.connected = imap_client_connected,
	.logout = imap_client_logout,
	.free = imap_client_free
};

struct imap_client *
imap_client_new(unsigned int idx, struct user *user, struct user_client *uc)
{
	struct imap_client *client;
	const char *mailbox;

	client = i_new(struct imap_client, 1);
	client->client.protocol = CLIENT_PROTOCOL_IMAP;
	client->client.port = conf.port != 0 ? conf.port : 143;
	if (client_init(&client->client, idx, user, uc) < 0) {
		i_free(client);
		return NULL;
	}

	if (strchr(conf.mailbox, '%') != NULL ||
	    client->client.user_client != NULL)
		client->try_create_mailbox = TRUE;
	i_array_init(&client->commands, 16);

	client->tag_counter = 1;
	mailbox = user_get_new_mailbox(&client->client);
	client->storage = mailbox_storage_get(user->mailbox_source,
					      user->username, mailbox);
	client->view = mailbox_view_new(client->storage);

	client->client.v = imap_client_vfuncs;
	client->handle_untagged = user->profile != NULL ?
		imap_client_profile_handle_untagged : imap_client_handle_untagged;
	client->client.v.send_more_commands = user->profile != NULL ?
		imap_client_profile_send_more_commands :
		imap_client_plan_send_more_commands;
        return client;
}
