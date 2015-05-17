/* Copyright (c) 2007-2015 Timo Sirainen */

#include "lib.h"
#include "array.h"
#include "base64.h"
#include "str.h"
#include "istream.h"
#include "ostream.h"

#include "settings.h"
#include "mailbox.h"
#include "profile.h"
#include "pop3-client.h"

#include <stdlib.h>
#include <unistd.h>

int pop3_client_input_error(struct pop3_client *client, const char *fmt, ...)
{
	va_list va;

	va_start(va, fmt);
	i_error("%s[%u]: %s: %s", client->client.user->username,
		client->client.global_id, t_strdup_vprintf(fmt, va),
		client->cur_line == NULL ? "" : client->cur_line);
	va_end(va);

	client_disconnect(&client->client);
	if (conf.error_quit)
		exit(2);
	return -1;
}

static void pop3_command_free(struct pop3_command *cmd)
{
	i_free(cmd->cmdline);
	i_free(cmd);
}

static void pop3_command_send(struct pop3_client *client, const char *cmdline,
			      pop3_command_callback_t *callback)
{
	struct pop3_command *cmd;

	cmd = i_new(struct pop3_command, 1);
	cmd->cmdline = i_strconcat(cmdline, "\r\n", NULL);
	cmd->state = client->client.state;
	cmd->callback = callback;
	gettimeofday(&cmd->tv_start, NULL);

	o_stream_send_str(client->client.output, cmd->cmdline);
	array_append(&client->commands, &cmd, 1);
}

static void
pop3_command_finish(struct pop3_client *client, struct pop3_command *cmd)
{
	struct pop3_command *const *cmds;
	unsigned int i, count;

	cmds = array_get(&client->commands, &count);
	for (i = 0; i < count; i++) {
		if (cmds[i] == cmd) {
			array_delete(&client->commands, i, 1);
			break;
		}
	}
	i_assert(i < count);

	counters[cmd->state]++;
	client_state_add_to_timer(cmd->state, &cmd->tv_start);
	pop3_command_free(cmd);
}

static int pop3_client_input_line(struct pop3_client *client, const char *line)
{
	struct pop3_command *const *cmdp;
	int ret;

	if (!client->seen_banner) {
		/* we haven't received the banner yet */
		client->seen_banner = TRUE;

		if (strncasecmp(line, "+OK", 3) != 0) {
			pop3_client_input_error(client, "Malformed banner");
			return -1;
		}
		return 0;
	}
	if (array_count(&client->commands) == 0) {
		pop3_client_input_error(client,
			"Received input while no commands were running");
		return -1;
	}
	cmdp = array_idx(&client->commands, 0);
	ret = (*cmdp)->callback(client, *cmdp, line);
	if (ret > 0)
		pop3_command_finish(client, *cmdp);
	return ret < 0 ? -1 : 0;
}

static void pop3_client_input(struct client *_client)
{
	struct pop3_client *client = (struct pop3_client *)_client;
	const char *line;
	int ret = 0;

	while ((line = i_stream_next_line(_client->input)) != NULL) {
		client->cur_line = line;
		T_BEGIN {
			ret = pop3_client_input_line(client, line);
		} T_END;
		if (ret < 0) {
			client_disconnect(_client);
			break;
		}
	}
	client->cur_line = NULL;
	(void)client_send_more_commands(&client->client);
}

static int pop3_client_output(struct client *_client ATTR_UNUSED)
{
	return 0;
}

static void pop3_client_connected(struct client *_client ATTR_UNUSED)
{
}

static void
pop3_client_authenticated(struct pop3_client *client, struct pop3_command *cmd)
{
	/* both AUTH and USER+PASS is two-step. remove the extra counters. */
	counters[cmd->state]--;
	client->client.login_state = LSTATE_AUTH;
}

static int
auth_plain_callback(struct pop3_client *client, struct pop3_command *cmd,
		    const char *line)
{
	struct client *_client = &client->client;
	buffer_t *str, *buf;

	if (line[0] != '+') {
		pop3_client_input_error(client, "Invalid reply to AUTH");
		return -1;
	}
	if (client->auth_reply_sent) {
		pop3_client_authenticated(client, cmd);
		return 1;
	}

	buf = t_str_new(512);
	if (conf.master_user != NULL) {
		str_append(buf, _client->user->username);
		str_append_c(buf, '\0');
		str_append(buf, conf.master_user);
	} else {
		str_append_c(buf, '\0');
		str_append(buf, _client->user->username);
	}
	str_append_c(buf, '\0');
	str_append(buf, _client->user->password);

	str = t_str_new(512);
	base64_encode(buf->data, buf->used, str);
	str_append(str, "\r\n");

	o_stream_send_str(_client->output, str_c(str));
	client->auth_reply_sent = TRUE;
	return 0;
}

static int pass_callback(struct pop3_client *client, struct pop3_command *cmd,
			 const char *line)
{
	if (line[0] != '+') {
		pop3_client_input_error(client, "Invalid reply to PASS");
		return -1;
	}
	pop3_client_authenticated(client, cmd);
	return 1;
}

static int user_callback(struct pop3_client *client,
			 struct pop3_command *cmd ATTR_UNUSED,
			 const char *line)
{
	struct client *_client = &client->client;
	const char *str;

	if (line[0] != '+') {
		pop3_client_input_error(client, "Invalid reply to USER");
		return -1;
	}

	str = t_strdup_printf("PASS %s", _client->user->password);
	pop3_command_send(client, str, pass_callback);
	return 1;
}

static void pop3_client_login(struct pop3_client *client)
{
	const char *cmd;

	client->client.state = do_rand(STATE_AUTHENTICATE) ?
		STATE_AUTHENTICATE : STATE_LOGIN;
	if (client->client.state == STATE_AUTHENTICATE) {
		pop3_command_send(client, "AUTH plain", auth_plain_callback);
	} else {
		cmd = t_strdup_printf("USER %s", client->client.user->username);
		pop3_command_send(client, cmd, user_callback);
	}
}

static int uidl_callback(struct pop3_client *client,
			 struct pop3_command *cmd ATTR_UNUSED,
			 const char *line)
{
	const char *uidl;

	if (!array_is_created(&client->uidls)) {
		p_array_init(&client->uidls, client->uidls_pool, 32);
		if (line[0] != '+') {
			pop3_client_input_error(client, "Invalid reply to UIDL");
			return -1;
		}
		client->uidls_matched = FALSE;
		return 0;
	} else if (strcmp(line, ".") != 0) {
		unsigned int idx = array_count(&client->uidls);
		uidl = p_strdup(client->uidls_pool, line);
		if (client->uidls_matched || client->client.user_client == NULL ||
		    !array_is_created(&client->client.user_client->pop3_uidls)) {
			/* no more UIDL checking */
		} else if (idx == array_count(&client->client.user_client->pop3_uidls))
			client->uidls_matched = TRUE;
		else {
			const char *const *old_uidlp =
				array_idx(&client->client.user_client->pop3_uidls, idx);
			if (strcmp(*old_uidlp, uidl) == 0)
				client->prev_seq++;
			else
				client->uidls_matched = TRUE;

		}
		array_append(&client->uidls, &uidl, 1);
		return 0;
	}
	client->uidls_matched = TRUE;
	return 1;
}

static int dele_callback(struct pop3_client *client,
			 struct pop3_command *cmd ATTR_UNUSED,
			 const char *line)
{
	if (line[0] != '+') {
		pop3_client_input_error(client, "Invalid reply to DELE");
		return -1;
	}
	return 1;
}

static int retr_callback(struct pop3_client *client,
			 struct pop3_command *cmd ATTR_UNUSED,
			 const char *line)
{
	if (!client->retr_reading) {
		client->retr_reading = TRUE;
		if (line[0] != '+') {
			pop3_client_input_error(client, "Invalid reply to RETR");
			return -1;
		}
		return 0;
	} else if (strcmp(line, ".") != 0) {
		return 0;
	} else {
		client->prev_seq++;
		if (!client->pop3_keep_mails) {
			client->client.state = STATE_EXPUNGE;
			pop3_command_send(client,
				t_strdup_printf("DELE %u", client->prev_seq),
				dele_callback);
		}
		client->retr_reading = FALSE;
		return 1;
	}
}

static int quit_callback(struct pop3_client *client,
			 struct pop3_command *cmd ATTR_UNUSED,
			 const char *line)
{
	if (line[0] != '+') {
		pop3_client_input_error(client, "Invalid reply to QUIT");
		return -1;
	}
	client->client.login_state = LSTATE_NONAUTH;
	return -1;
}

static int pop3_client_send_more_commands(struct client *_client)
{
	struct pop3_client *client = (struct pop3_client *)_client;

	if (array_count(&client->commands) > 0)
		return 0;

	switch (client->client.login_state) {
	case LSTATE_NONAUTH:
		/* we begin with USER/AUTH commands */
		pop3_client_login(client);
		break;
	case LSTATE_AUTH:
	case LSTATE_SELECTED:
		if (!array_is_created(&client->uidls)) {
			_client->state = STATE_SELECT;
			pop3_command_send(client, "UIDL", uidl_callback);
		} else if (client->prev_seq < array_count(&client->uidls)) {
			_client->state = STATE_FETCH2;
			pop3_command_send(client,
				t_strdup_printf("RETR %u", client->prev_seq+1),
				retr_callback);
		} else {
			counters[STATE_LOGOUT]++;
			client_logout(_client);
		}
		break;
	}
	i_assert(_client->state <= STATE_LOGOUT);

	if (!_client->delayed && do_rand(STATE_DELAY)) {
		counters[STATE_DELAY]++;
		client_delay(&client->client, rand() % DELAY_MSECS);
	}
	return 0;
}

static void pop3_client_logout(struct client *_client)
{
	struct pop3_client *client = (struct pop3_client *)_client;

	client->client.logout_sent = TRUE;
	pop3_command_send(client, "QUIT", quit_callback);
}

static void pop3_client_free(struct client *_client)
{
	struct pop3_client *client = (struct pop3_client *)_client;
	struct user_client *uc = client->client.user_client;
	struct pop3_command *const *cmds;
	unsigned int i, count;

	if (conf.disconnect_quit && _client->login_state != LSTATE_NONAUTH)
		exit(1);
	cmds = array_get(&client->commands, &count);

	if (uc != NULL && client->uidls_matched) {
		/* remember UIDLs for all mails we RETRed */
		array_delete(&client->uidls, client->prev_seq,
			     array_count(&client->uidls) - client->prev_seq);

		if (uc->pop3_uidls_pool != NULL)
			pool_unref(&uc->pop3_uidls_pool);
		uc->pop3_uidls_pool = client->uidls_pool;
		uc->pop3_uidls = client->uidls;
	} else {
		if (array_is_created(&client->uidls))
			array_free(&client->uidls);
		pool_unref(&client->uidls_pool);
	}

	for (i = 0; i < count; i++)
		pop3_command_free(cmds[i]);
	array_free(&client->commands);
}

static const struct client_vfuncs pop3_client_vfuncs = {
	pop3_client_input,
	pop3_client_output,
	pop3_client_connected,
	pop3_client_send_more_commands,
	pop3_client_logout,
	pop3_client_free
};

struct pop3_client *
pop3_client_new(unsigned int idx, struct user *user, struct user_client *uc)
{
	struct pop3_client *client;

	client = i_new(struct pop3_client, 1);
	client->client.protocol = CLIENT_PROTOCOL_POP3;
	client->client.port = conf.port != 0 ? conf.port : 110;
	if (client_init(&client->client, idx, user, uc) < 0) {
		i_free(client);
		return NULL;
	}

	client->pop3_keep_mails = uc != NULL && uc->profile->pop3_keep_mails;
	client->uidls_pool = pool_alloconly_create("pop3 client", 1024);
	i_array_init(&client->commands, 16);
	client->client.v = pop3_client_vfuncs;
        return client;
}
