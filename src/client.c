/* Copyright (c) 2007-2008 Timo Sirainen */

#include "lib.h"
#include "ioloop.h"
#include "array.h"
#include "istream.h"
#include "ostream.h"
#include "iostream-rawlog.h"
#include "iostream-ssl.h"
#include "str.h"
#include "imap-parser.h"

#include "imap-seqset.h"
#include "imap-util.h"
#include "settings.h"
#include "mailbox.h"
#include "mailbox-state.h"
#include "commands.h"
#include "checkpoint.h"
#include "search.h"
#include "test-exec.h"
#include "client.h"

#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

int clients_count = 0;
unsigned int total_disconnects = 0;
ARRAY_TYPE(client) clients;
ARRAY(unsigned int) stalled_clients;
bool stalled = FALSE, disconnect_clients = FALSE, no_new_clients = FALSE;

static unsigned int global_id_counter = 0;
static struct ssl_iostream_context *ssl_ctx = NULL;

static const struct ssl_iostream_settings ssl_set;

int client_input_error(struct client *client, const char *fmt, ...)
{
	va_list va;

	va_start(va, fmt);
	i_error("%s[%u]: %s: %s", client->username, client->global_id,
		t_strdup_vprintf(fmt, va), client->cur_args == NULL ? "" :
		imap_args_to_str(client->cur_args));
	va_end(va);

	client_disconnect(client);
	if (conf.error_quit)
		exit(2);
	return -1;
}

int client_input_warn(struct client *client, const char *fmt, ...)
{
	va_list va;

	va_start(va, fmt);
	i_error("%s[%u]: %s: %s", client->username, client->global_id,
		t_strdup_vprintf(fmt, va), client->cur_args == NULL ? "" :
		imap_args_to_str(client->cur_args));
	va_end(va);
	return -1;
}

int client_state_error(struct client *client, const char *fmt, ...)
{
	va_list va;

	va_start(va, fmt);
	i_error("%s[%u]: %s: %s", client->username, client->global_id,
		t_strdup_vprintf(fmt, va), client->cur_args == NULL ? "" :
		imap_args_to_str(client->cur_args));
	va_end(va);

	if (conf.error_quit)
		exit(2);
	return -1;
}

void client_exists(struct client *client, unsigned int msgs)
{
	unsigned int old_count = array_count(&client->view->uidmap);

	if (msgs < old_count) {
		client_input_error(client, "Message count dropped %u -> %u",
				   old_count, msgs);
		array_delete(&client->view->uidmap, msgs, old_count - msgs);
		return;
	}
	for (; old_count < msgs; old_count++)
		(void)array_append_space(&client->view->uidmap);
}

static int client_expunge(struct client *client, unsigned int seq)
{
	struct message_metadata_dynamic *metadata;
	unsigned int count = array_count(&client->view->uidmap);

	if (seq == 0) {
		client_input_error(client, "Tried to expunge sequence 0");
		return -1;
	}
	if (seq > count) {
		client_input_error(client,
			"Tried to expunge sequence %u with only %u msgs",
			seq, count);
		return -1;
	}

	metadata = array_idx_modifiable(&client->view->messages, seq - 1);
	if (metadata->fetch_refcount > 0) {
		client_input_error(client,
			"Referenced message expunged seq=%u uid=%u",
			seq, metadata->ms == NULL ? 0 : metadata->ms->uid);
		return -1;
	}
	mailbox_view_expunge(client->view, seq);
	return 0;
}

static int client_expunge_uid(struct client *client, uint32_t uid)
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
				client_expunge(client, i + 1);
				return 0;
			}
			break;
		}
	}

	/* there are one or more unknown messages. expunge the last one of them
	   (none of them should have any attached metadata) */
	if (i == 0 || uidmap[i-1] != 0) {
		client_input_error(client, "VANISHED UID=%u not found", uid);
		return -1;
	}

	client_expunge(client, i);
	return 0;
}

static void
client_expunge_uid_range(struct client *client,
			 const ARRAY_TYPE(seq_range) *expunged_uids)
{
	const uint32_t *uidmap;
	unsigned int seq, uid_count;

	uidmap = array_get(&client->view->uidmap, &uid_count);
	for (seq = uid_count; seq > 0; seq--) {
		i_assert(uidmap[seq-1] != 0);

		if (seq_range_exists(expunged_uids, uidmap[seq-1])) {
			client_expunge(client, seq);
			uidmap = array_get(&client->view->uidmap, &uid_count);
		}
	}
}

static void client_enabled(struct client *client, const struct imap_arg *args)
{
	const char *str;

	for (; imap_arg_get_atom(args, &str); args++) {
		if (strcasecmp(str, "QRESYNC") == 0)
			client->qresync_enabled = TRUE;
	}
}

static int client_vanished(struct client *client, const struct imap_arg *args)
{
	struct mailbox_view *view = client->view;
	const struct imap_arg *subargs;
	ARRAY_TYPE(seq_range) uids;
	const struct seq_range *range;
	unsigned int i, count;
	const char *uidset;
	uint32_t uid;

	if (!client->qresync_enabled) {
		client_input_error(client,
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
		client_input_error(client, "Invalid VANISHED parameters");
		return -1;
	}

	t_array_init(&uids, 16);
	if (imap_seq_set_parse(uidset, &uids) < 0) {
		client_input_error(client, "Invalid VANISHED sequence-set");
		return -1;
	}

	if (view->known_uid_count == array_count(&view->uidmap)) {
		/* all UIDs are known - we can handle UIDs that are already
		   expunged. this happens normally when doing a SELECT QRESYNC
		   and server couldn't keep track of only the new expunges. */
		client_expunge_uid_range(client, &uids);
		return 0;
	}

	/* we assume that there are no extra UIDs in the reply, even though
	   it's only a SHOULD in the spec. way too difficult to handle
	   otherwise. */
	range = array_get(&uids, &count);
	for (i = 0; i < count; i++) {
		for (uid = range[i].seq1; uid <= range[i].seq2; uid++)
			client_expunge_uid(client, uid);
	}
	return 0;
}

void client_capability_parse(struct client *client, const char *line)
{
	const char *const *tmp;
	unsigned int i;

	if (client->login_state != LSTATE_NONAUTH)
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

int client_handle_untagged(struct client *client, const struct imap_arg *args)
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
			client_exists(client, num);

                if (num > array_count(&view->uidmap) &&
		    client->last_cmd->state > STATE_SELECT) {
			client_input_warn(client,
				"seq too high (%u > %u, state=%s)",
				num, array_count(&view->uidmap),
                                states[client->last_cmd->state].name);
		} else if (strcmp(str, "EXPUNGE") == 0) {
			if (client_expunge(client, num) < 0)
				return -1;
		} else if (strcmp(str, "RECENT") == 0) {
			view->recent_count = num;
			if (view->recent_count ==
			    array_count(&view->uidmap))
				view->storage->seen_all_recent = TRUE;
		} else if (!conf.no_tracking && strcmp(str, "FETCH") == 0)
			mailbox_state_handle_fetch(client, num, args);
	} else if (strcmp(str, "BYE") == 0) {
		if (client->last_cmd == NULL ||
		    client->last_cmd->state != STATE_LOGOUT)
			client_input_warn(client, "Unexpected BYE");
		else
			counters[client->last_cmd->state]++;
		client_mailbox_close(client);
		client->login_state = LSTATE_NONAUTH;
	} else if (strcmp(str, "FLAGS") == 0) {
		if (mailbox_state_set_flags(view, args) < 0)
			client_input_error(client, "Broken FLAGS");
	} else if (strcmp(str, "CAPABILITY") == 0)
		client_capability_parse(client, imap_args_to_str(args));
	else if (strcmp(str, "SEARCH") == 0)
		search_result(client, args);
	else if (strcmp(str, "ENABLED") == 0)
		client_enabled(client, args);
	else if (strcmp(str, "VANISHED") == 0) {
		if (client_vanished(client, args) < 0)
			return -1;
	} else if (strcmp(str, "THREAD") == 0) {
		i_free(view->last_thread_reply);
		view->last_thread_reply = IMAP_ARG_IS_EOL(args) ?
			i_strdup("") :
			i_strdup(imap_args_to_str(args + 1));
	} else if (strcmp(str, "OK") == 0) {
		client_handle_resp_text_code(client, args);
	} else if (strcmp(str, "NO") == 0) {
		/*i_info("%s: %s", client->username, line + 2);*/
	} else if (strcmp(str, "BAD") == 0) {
		client_input_warn(client, "BAD received");
	}
	return 0;
}

static int
client_input_args(struct client *client, const struct imap_arg *args)
{
	const char *p, *tag, *tag_status;
	struct command *cmd;
	enum command_reply reply;

	if (!imap_arg_get_atom(args, &tag))
		return client_input_error(client, "Broken tag");
	args++;

	if (strcmp(tag, "+") == 0) {
		if (client->last_cmd == NULL) {
			return client_input_error(client,
				"Unexpected command continuation");
		}
		client->last_cmd->callback(client, client->last_cmd,
					   args, REPLY_CONT);
		return 0;
	}
	if (strcmp(tag, "*") == 0) {
		if (client->handle_untagged(client, args) < 0) {
			return client_input_error(client,
						  "Invalid untagged input");
		}
		return 0;
	}

	/* tagged reply */
	if (!imap_arg_get_atom(args, &tag_status))
		return client_input_error(client, "Broken tagged reply");

	p = strchr(tag, '.');
	cmd = p != NULL &&
		atoi(t_strdup_until(tag, p)) == (int)client->global_id ?
		command_lookup(client, atoi(t_strcut(p+1, ' '))) : NULL;
	if (cmd == NULL) {
		return client_input_error(client, "Unexpected tagged reply: %s",
					  tag);
	}

	if (strcasecmp(tag_status, "OK") == 0)
		reply = REPLY_OK;
	else if (strcasecmp(tag_status, "NO") == 0)
		reply = REPLY_NO;
	else if (strcasecmp(tag_status, "BAD") == 0) {
		reply = REPLY_BAD;
		if (!cmd->expect_bad) {
			client_input_error(client, "BAD reply for command: %s",
					   cmd->cmdline);
		}
	} else {
		return client_input_error(client, "Broken tagged reply");
	}

	command_unlink(client, cmd);

	o_stream_cork(client->output);
	cmd->callback(client, cmd, args, reply);
	client_cmd_reply_finish(client);
	o_stream_uncork(client->output);
	command_free(cmd);
	return 0;
}

static bool client_skip_literal(struct client *client)
{
	size_t size;

	if (client->literal_left == 0)
		return TRUE;

	(void)i_stream_get_data(client->input, &size);
	if (size < client->literal_left) {
		client->literal_left -= size;
		i_stream_skip(client->input, size);
		return FALSE;
	} else {
		i_stream_skip(client->input, client->literal_left);
		client->literal_left = 0;
		return TRUE;
	}
}

static void client_input(struct client *client)
{
	const struct imap_arg *imap_args;
	const char *line, *p;
	uoff_t literal_size;
	const unsigned char *data;
	size_t size;
	bool fatal;
	int ret;

	client->last_io = ioloop_time;

	switch (i_stream_read(client->input)) {
	case 0:
		return;
	case -1:
		/* disconnected */
		client_unref(client, TRUE);
		return;
	case -2:
		/* buffer full */
		i_error("line too long");
		client_unref(client, TRUE);
		return;
	}

	if (!client->seen_banner) {
		/* we haven't received the banner yet */
		line = i_stream_next_line(client->input);
		if (line == NULL)
			return;
		client->seen_banner = TRUE;

		p = strstr(line, "[CAPABILITY ");
		if (p == NULL)
			command_send(client, "CAPABILITY", state_callback);
		else {
			client_capability_parse(client, t_strcut(p + 12, ']'));
			(void)client_send_more_commands(client);
		}
	}

	while (client_skip_literal(client)) {
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
			client_input_error(client,
				"error parsing input: %s",
				imap_parser_get_error(client->parser, &fatal));
			return;
		}
		if (imap_args->type == IMAP_ARG_EOL) {
			/* FIXME: we get here, but we shouldn't.. */
			client->refcount++;
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
			client->refcount++;
			client->cur_args = imap_args;
			t_push();
			ret = client_input_args(client, imap_args);
			t_pop();
			client->cur_args = NULL;
		}

		if (client->literal_left == 0) {
			/* end of command - skip CRLF */
			imap_parser_reset(client->parser);

			data = i_stream_get_data(client->input, &size);
			if (size > 0 && data[0] == '\r') {
				i_stream_skip(client->input, 1);
				data = i_stream_get_data(client->input, &size);
			}
			if (size > 0 && data[0] == '\n')
				i_stream_skip(client->input, 1);
		}

		if (!client_unref(client, TRUE) || ret < 0)
			return;
	}

	if (do_rand(STATE_DISCONNECT)) {
		/* random disconnection */
		counters[STATE_DISCONNECT]++;
		client_unref(client, TRUE);
		return;
	}

	(void)i_stream_get_data(client->input, &client->prev_size);
	if (client->input->closed)
		client_unref(client, TRUE);
}

void client_input_stop(struct client *client)
{
	if (client->io != NULL)
		io_remove(&client->io);
}

void client_input_continue(struct client *client)
{
	if (client->io == NULL && !client->input->closed)
		client->io = io_add(client->fd, IO_READ, client_input, client);
}

static void client_delay_timeout(struct client *client)
{
	i_assert(client->io == NULL);

	client->delayed = FALSE;
	client->last_io = ioloop_time;

	timeout_remove(&client->to);
	client_input_continue(client);
}

void client_delay(struct client *client, unsigned int msecs)
{
	if (client->input->closed) {
		/* we're already disconnected and client->to is set */
		return;
	}
	i_assert(client->to == NULL);

	client->delayed = TRUE;
	io_remove(&client->io);
	client->to = timeout_add(msecs, client_delay_timeout, client);
}

static int client_output(struct client *client)
{
	int ret;

	o_stream_cork(client->output);
	ret = o_stream_flush(client->output);
	client->last_io = ioloop_time;

	if (client->append_vsize_left > 0 && client->append_can_send) {
		if (client_append_continue(client) < 0)
			client_unref(client, TRUE);
	}
	o_stream_uncork(client->output);

        return ret;
}

static void client_wait_connect(struct client *client)
{
	const char *error;
	int err;

	err = net_geterror(client->fd);
	if (err != 0) {
		i_error("connect() failed: %s", strerror(err));
		client_unref(client, TRUE);
		return;
	}

	if (conf.port == 993) {
		if (ssl_ctx == NULL) {
			if (ssl_iostream_context_init_client(&ssl_set, &ssl_ctx, &error) < 0)
				i_fatal("Failed to initialize SSL context: %s", error);
		}
		if (io_stream_create_ssl_client(ssl_ctx, conf.host, &ssl_set,
						&client->input, &client->output,
						&client->ssl_iostream, &error) < 0)
			i_fatal("Couldn't create SSL iostream: %s", error);
		(void)ssl_iostream_handshake(client->ssl_iostream);
	}
	if (conf.rawlog) {
		if (iostream_rawlog_create_path(
				t_strdup_printf("rawlog.%u", client->global_id),
				&client->input, &client->output))
			client->rawlog_fd = o_stream_get_fd(client->output);
	}

	io_remove(&client->io);
	client->io = io_add(client->fd, IO_READ, client_input, client);
	client->parser = imap_parser_create(client->input, NULL, (size_t)-1);
}

static void client_set_random_user(struct client *client)
{
	static int prev_user = 0, prev_domain = 0;
	const char *const *userp, *p;
	unsigned int i;

	if (array_is_created(&conf.usernames)) {
		i = rand() % array_count(&conf.usernames);
		userp = array_idx(&conf.usernames, i);
		p = strchr(*userp, ':');
		if (p == NULL) {
			client->username = i_strdup(*userp);
			client->password = i_strdup(conf.password);
		} else {
			client->username = i_strdup_until(*userp, p);
			client->password = i_strdup(p + 1);
		}
		i_assert(*client->username != '\0');
	} else {
		if (rand() % 2 == 0 && prev_user != 0) {
			/* continue with same user */
		} else {
			prev_user = random() % USER_RAND + 1;
			prev_domain = random() % DOMAIN_RAND + 1;
		}
		client->username =
			i_strdup_printf(conf.username_template,
					prev_user, prev_domain);
		client->password = i_strdup(conf.password);
	}
}

struct client *client_new(unsigned int idx, struct mailbox_source *source,
			  const char *username)
{
	struct client *client;
	const struct ip_addr *ip;
	const char *mailbox;
	int fd;

	i_assert(idx >= array_count(&clients) ||
		 *(struct client **)array_idx(&clients, idx) == NULL);
	/*if (stalled) {
		array_append(&stalled_clients, &idx, 1);
		return NULL;
	}*/

	ip = &conf.ips[conf.ip_idx];
	fd = net_connect_ip(ip, conf.port, NULL);
	if (++conf.ip_idx == conf.ips_count)
		conf.ip_idx = 0;

	if (fd < 0) {
		i_error("connect() failed: %m");
		return NULL;
	}

	client = i_new(struct client, 1);
	client->refcount = 1;
	client->tag_counter = 1;
	client->idx = idx;
	client->global_id = ++global_id_counter;
	if (username != NULL) {
		client->username = i_strdup(username);
		client->password = i_strdup(conf.password);
	} else {
		client_set_random_user(client);
	}

	mailbox = t_strdup_printf(conf.mailbox, idx);
	client->storage = mailbox_storage_get(source, client->username, mailbox);
	client->view = mailbox_view_new(client->storage);
	if (strchr(conf.mailbox, '%') != NULL)
		client->try_create_mailbox = TRUE;
	client->fd = fd;
	client->rawlog_fd = -1;
	client->input = i_stream_create_fd(fd, 1024*64, FALSE);
	client->output = o_stream_create_fd(fd, (size_t)-1, FALSE);
	o_stream_set_flush_callback(client->output, client_output, client);
	client->io = io_add(fd, IO_WRITE, client_wait_connect, client);
        client->last_io = ioloop_time;
	i_array_init(&client->commands, 16);
	clients_count++;

	client->handle_untagged = client_handle_untagged;
	client->send_more_commands = client_plan_send_more_commands;

        array_idx_set(&clients, idx, &client);
        return client;
}

void client_disconnect(struct client *client)
{
	client->disconnected = TRUE;

	i_stream_close(client->input);
	o_stream_close(client->output);

	if (client->io != NULL)
		io_remove(&client->io);
	if (client->to != NULL)
		timeout_remove(&client->to);
	client->to = timeout_add(0, client_input, client);
}

bool client_unref(struct client *client, bool reconnect)
{
	struct mailbox_storage *storage = client->storage;
	unsigned int idx = client->idx;
	struct command *const *cmds;
	unsigned int i, count;
	bool checkpoint;

	i_assert(client->refcount > 0);
	if (--client->refcount > 0)
		return TRUE;

	total_disconnects++;
	if (conf.disconnect_quit && client->login_state != LSTATE_NONAUTH)
		exit(1);

	if (--clients_count == 0)
		stalled = FALSE;
	array_idx_clear(&clients, idx);

	cmds = array_get(&client->commands, &count);
	checkpoint = client->checkpointing != NULL && count > 0;
	for (i = 0; i < count; i++)
		command_free(cmds[i]);
	array_free(&client->commands);

	if (client->qresync_select_cache != NULL)
		mailbox_offline_cache_unref(&client->qresync_select_cache);

	client_mailbox_close(client);
	mailbox_view_free(&client->view);

	o_stream_destroy(&client->output);
	i_stream_destroy(&client->input);
	if (client->ssl_iostream != NULL)
		ssl_iostream_destroy(&client->ssl_iostream);
	if (client->io != NULL)
		io_remove(&client->io);
	if (client->to != NULL)
		timeout_remove(&client->to);
	if (close(client->fd) < 0)
		i_error("close(client) failed: %m");

	if (client->test_exec_ctx != NULL) {
		/* storage must be fully unreferenced before new test can
		   begin. */
		mailbox_storage_unref(&storage);
		test_execute_cancel_by_client(client);
	}
	if (client->parser != NULL)
		imap_parser_unref(&client->parser);

	if (client->capabilities_list != NULL)
		p_strsplit_free(default_pool, client->capabilities_list);
	i_free(client->username);
	i_free(client->password);

	if (clients_count == 0 && disconnect_clients)
		io_loop_stop(current_ioloop);
	else if (io_loop_is_running(current_ioloop) && !no_new_clients &&
		 !disconnect_clients && reconnect) {
		client_new(idx, storage->source, NULL);
		if (!stalled) {
			const unsigned int *indexes;
			unsigned int i, count;

			indexes = array_get(&stalled_clients, &count);
			for (i = 0; i < count && i < 3; i++)
				client_new(indexes[i], storage->source, NULL);
			array_delete(&stalled_clients, 0, i);
		}
	}
	i_free(client);

	if (storage != NULL) {
		if (checkpoint)
			checkpoint_neg(storage);
		mailbox_storage_unref(&storage);
	}
	return FALSE;
}

void client_log_mailbox_view(struct client *client)
{
	const struct message_metadata_dynamic *metadata;
	const uint32_t *uidmap;
	unsigned int i, count, metadata_count;
	string_t *str;

	if (client->rawlog_fd == -1)
		return;
	(void)o_stream_flush(client->output);

	str = t_str_new(256);
	str_printfa(str, "** view: highest_modseq=%llu\r\n",
		    (unsigned long long)client->view->highest_modseq);
	write(client->rawlog_fd, str_data(str), str_len(str));

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
		write(client->rawlog_fd, str_data(str), str_len(str));
	}
	write(client->rawlog_fd, "**\r\n", 4);
}

void client_mailbox_close(struct client *client)
{
	if (client->login_state == LSTATE_SELECTED && conf.qresync) {
		if (rand() % 3 == 0) {
			if (mailbox_view_save_offline_cache(client->view))
				client_log_mailbox_view(client);
		}

		client->login_state = LSTATE_AUTH;
	}
	mailbox_view_free(&client->view);
	client->view = mailbox_view_new(client->storage);
}

int client_send_more_commands(struct client *client)
{
	int ret;

	o_stream_cork(client->output);
	ret = client->send_more_commands(client);
	o_stream_uncork(client->output);
	return ret;
}

unsigned int clients_get_random_idx(void)
{
	struct client *const *c;
	unsigned int i, idx, count;

	/* first try randomly */
	c = array_get(&clients, &count);
	for (i = 0; i < 100; i++) {
		idx = rand() % count;
		if (c[idx] != NULL)
			return idx;
	}
	/* then just try anything */
	for (i = 0; i < count; i++) {
		if (c[i] != NULL)
			return i;
	}
	i_unreached();
	return 0;
}

void clients_init(void)
{
	i_array_init(&stalled_clients, CLIENTS_COUNT);
}

void clients_deinit(void)
{
	if (ssl_ctx != NULL)
		ssl_iostream_context_deinit(&ssl_ctx);
	array_free(&stalled_clients);
}
