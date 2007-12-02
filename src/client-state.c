/* Copyright (C) 2007 Timo Sirainen */

#include "lib.h"
#include "base64.h"
#include "str.h"
#include "istream.h"
#include "ostream.h"
#include "imap-date.h"
#include "imap-parser.h"

#include "imap-args.h"
#include "settings.h"
#include "mailbox.h"
#include "mailbox-source.h"
#include "checkpoint.h"
#include "commands.h"
#include "client.h"
#include "client-state.h"

#include <stdlib.h>

struct state states[STATE_COUNT] = {
	{ "BANNER",	  "Bann", LSTATE_NONAUTH,  0,   0,  0 },
	{ "AUTHENTICATE", "Auth", LSTATE_NONAUTH,  0,   0,  FLAG_STATECHANGE | FLAG_STATECHANGE_AUTH },
	{ "LOGIN",	  "Logi", LSTATE_NONAUTH,  100, 0,  FLAG_STATECHANGE | FLAG_STATECHANGE_AUTH },
	{ "LIST",	  "List", LSTATE_AUTH,     50,  0,  FLAG_EXPUNGES },
	{ "MCREATE",	  "MCre", LSTATE_AUTH,     0,   0,  FLAG_EXPUNGES },
	{ "MDELETE",	  "MDel", LSTATE_AUTH,     0,   0,  FLAG_EXPUNGES },
	{ "STATUS",	  "Stat", LSTATE_AUTH,     50,  0,  FLAG_EXPUNGES },
	{ "SELECT",	  "Sele", LSTATE_AUTH,     100, 0,  FLAG_STATECHANGE | FLAG_STATECHANGE_SELECTED },
	{ "FETCH",	  "Fetc", LSTATE_SELECTED, 100, 0,  FLAG_MSGSET },
	{ "FETCH2",	  "Fet2", LSTATE_SELECTED, 100, 30, FLAG_MSGSET },
	{ "SEARCH",	  "Sear", LSTATE_SELECTED, 0,   0,  0 },
	{ "SORT",	  "Sort", LSTATE_SELECTED, 0,   0,  0 },
	{ "THREAD",	  "Thre", LSTATE_SELECTED, 0,   0,  0 },
	{ "COPY",	  "Copy", LSTATE_SELECTED, 33,  5,  FLAG_MSGSET | FLAG_EXPUNGES },
	{ "STORE",	  "Stor", LSTATE_SELECTED, 50,  0,  FLAG_MSGSET },
	{ "DELETE",	  "Dele", LSTATE_SELECTED, 100, 0,  FLAG_MSGSET },
	{ "EXPUNGE",	  "Expu", LSTATE_SELECTED, 100, 0,  FLAG_EXPUNGES },
	{ "APPEND",	  "Appe", LSTATE_AUTH,     100, 5,  FLAG_EXPUNGES },
	{ "NOOP",	  "Noop", LSTATE_AUTH,     0,   0,  FLAG_EXPUNGES },
	{ "CHECK",	  "Chec", LSTATE_AUTH,     0,   0,  FLAG_EXPUNGES },
	{ "LOGOUT",	  "Logo", LSTATE_NONAUTH,  100, 0,  FLAG_STATECHANGE | FLAG_STATECHANGE_NONAUTH },
	{ "DISCONNECT",	  "Disc", LSTATE_NONAUTH,  0,   0,  0 },
	{ "DELAY",	  "Dela", LSTATE_NONAUTH,  0,   0,  0 },
	{ "CHECKPOINT!",  "ChkP", LSTATE_NONAUTH,  0,   0,  0 }
};

unsigned int counters[STATE_COUNT], total_counters[STATE_COUNT];

bool do_rand(enum client_state state)
{
	return (rand() % 100) < states[state].probability;
}

bool do_rand_again(enum client_state state)
{
	return (rand() % 100) < states[state].probability_again;
}

static void auth_plain_callback(struct client *client, struct command *cmd,
				const struct imap_arg *args,
				enum command_reply reply)
{
	buffer_t *str, *buf;

	if (reply == REPLY_OK) {
		state_callback(client, cmd, args, reply);
		return;
	}
	if (reply != REPLY_CONT) {
		client_input_error(client, "AUTHENTICATE failed");
		client_unref(client);
		return;
	}

	counters[cmd->state]++;

	buf = t_str_new(512);
	str_append_c(buf, '\0');
	str_append(buf, client->username);
	str_append_c(buf, '\0');
	str_append(buf, conf.password);

	str = t_str_new(512);
	base64_encode(buf->data, buf->used, str);
	str_append(str, "\r\n");

	o_stream_send_str(client->output, str_c(str));
}

static enum client_state client_eat_first_plan(struct client *client)
{
	enum client_state state;

	if (disconnect_clients)
		return STATE_LOGOUT;

	i_assert(client->plan_size > 0);
	state = client->plan[0];

	client->plan_size--;
	memmove(client->plan, client->plan + 1,
		sizeof(client->plan[0]) * client->plan_size);
	return state;
}

static enum client_state client_get_next_state(enum client_state state)
{
	i_assert(state < STATE_LOGOUT);

	for (;;) {
		if (!conf.random_states)
			state++;
		else {
			/* if we're not in selected state, we'll randomly do
			   LIST, SELECT, APPEND or LOGOUT */
			state = STATE_LIST +
				(rand() % (STATE_LOGOUT - STATE_LIST + 1));
		}

		if (do_rand(state))
			break;

		if (state == STATE_LOGOUT) {
			/* logout skipped, wrap */
			state = STATE_AUTHENTICATE + 1;
		}
	}
	return state;
}

static enum login_state flags2login_state(enum state_flags flags)
{
	if ((flags & FLAG_STATECHANGE_NONAUTH) != 0)
		return LSTATE_NONAUTH;
	else if ((flags & FLAG_STATECHANGE_AUTH) != 0)
		return LSTATE_AUTH;
	else if ((flags & FLAG_STATECHANGE_SELECTED) != 0)
		return LSTATE_SELECTED;

	i_unreached();
}

static enum state_flags
client_get_pending_cmd_flags(struct client *client,
			     enum login_state *new_lstate_r)
{
	enum state_flags state_flags = 0;
	struct command *const *cmds;
	unsigned int i, count;

	*new_lstate_r = client->login_state;
	cmds = array_get(&client->commands, &count);
	for (i = 0; i < count; i++) {
		enum state_flags flags = states[cmds[i]->state].flags;

		if ((flags & FLAG_STATECHANGE) != 0)
			*new_lstate_r = flags2login_state(flags);
		state_flags |= flags;
	}
	return state_flags;
}

enum client_state client_update_plan(struct client *client)
{
	enum client_state state;
	enum login_state lstate;

	state = client->plan_size > 0 ?
		client->plan[client->plan_size - 1] : client->plan[0];
	if (client->plan_size > 0 &&
	    (states[state].flags & FLAG_STATECHANGE) != 0) {
		/* wait until the state change is done before making new
		   commands. */
		return client->plan[0];
	}
	if ((client_get_pending_cmd_flags(client, &lstate) &
	     FLAG_STATECHANGE) != 0)
		return state;

	if (state == STATE_LOGOUT)
		return state;

	while (client->plan_size <
	       sizeof(client->plan)/sizeof(client->plan[0])) {
		switch (client->login_state) {
		case LSTATE_NONAUTH:
			/* we begin with LOGIN/AUTHENTICATE commands */
			i_assert(client->plan_size == 0);
			state = do_rand(STATE_AUTHENTICATE) ?
				STATE_AUTHENTICATE : STATE_LOGIN;
			break;
		case LSTATE_AUTH:
		case LSTATE_SELECTED:
			if (!do_rand_again(state))
				state = client_get_next_state(state);
			break;
		}
		i_assert(state <= STATE_LOGOUT);

		if (states[state].login_state > client->login_state ||
		    (client->login_state != LSTATE_NONAUTH &&
		     (state == STATE_AUTHENTICATE || state == STATE_LOGIN))) {
			/* can't do this now */
			continue;
		}

		client->plan[client->plan_size++] = state;
		if ((states[state].flags & FLAG_STATECHANGE) != 0)
			break;
	}

	i_assert(client->plan_size > 0);
	state = client->plan[0];
	i_assert(states[state].login_state <= client->login_state);
	return state;
}

static bool client_pending_cmds_allow_statechange(struct client *client,
						  enum client_state state)
{
	enum login_state old_lstate, new_lstate = 0;
	struct command *const *cmds;
	unsigned int i, count;

	new_lstate = flags2login_state(states[state].flags);

	cmds = array_get(&client->commands, &count);
	for (i = 0; i < count; i++) {
		if ((states[cmds[i]->state].flags & FLAG_STATECHANGE) != 0)
			return FALSE;

		old_lstate = states[cmds[i]->state].login_state;
		if (new_lstate < old_lstate)
			return FALSE;
		if (new_lstate == old_lstate && new_lstate == LSTATE_SELECTED)
			return FALSE;
	}
	return TRUE;
}

int client_send_more_commands(struct client *client)
{
	enum state_flags pending_flags;
	enum login_state new_lstate;
	enum client_state state;

	while (array_count(&client->commands) < MAX_COMMAND_QUEUE_LEN) {
		state = client_update_plan(client);
		i_assert(state <= STATE_LOGOUT);

		if (client->append_unfinished)
			break;
		if (conf.no_pipelining && array_count(&client->commands) > 0)
			break;

		if ((states[state].flags & FLAG_STATECHANGE) != 0) {
			/* this command would change the state. check if there
			   are any pending commands that don't like the
			   change */
			if (!client_pending_cmds_allow_statechange(client,
								   state))
				break;
		}
		pending_flags = client_get_pending_cmd_flags(client,
							     &new_lstate);
		if ((states[state].flags & FLAG_STATECHANGE) == 0 &&
		    (pending_flags & FLAG_STATECHANGE) != 0) {
			/* we're changing state. allow this command if its
			   required login_state is lower than the current
			   state or the state we're changing to. */
			if (new_lstate <= states[state].login_state ||
			    client->login_state < states[state].login_state)
				break;
		}
		if ((states[state].flags & FLAG_MSGSET) != 0 &&
		    (pending_flags & (FLAG_EXPUNGES | FLAG_STATECHANGE)) != 0) {
			/* msgset may become invalid if we send it now */
			break;
		}

		if (client_send_next_cmd(client) < 0)
			return -1;
	}

	if (!client->delayed && do_rand(STATE_DELAY)) {
		counters[STATE_DELAY]++;
		client_delay(client, DELAY);
	}
	return 0;
}

int client_append(struct client *client, bool continued)
{
	struct mailbox_source *source = client->view->storage->source;
	string_t *cmd;
	struct istream *input;
	time_t t;
	off_t ret;

	if (!continued) {
		i_assert(client->append_size == 0);
		mailbox_source_get_next_size(source, &client->append_size, &t);
		client->append_offset = source->input->v_offset;

		cmd = t_str_new(128);
		if (!client->append_unfinished)
			str_printfa(cmd, "APPEND \"%s\"", conf.mailbox);
		if ((rand() % 2) == 0) {
			str_printfa(cmd, " (%s)",
				mailbox_view_get_random_flags(client->view));
		}
		if ((rand() % 2) == 0)
			str_printfa(cmd, " \"%s\"", imap_to_datetime(t));
		str_printfa(cmd, " {%"PRIuUOFF_T, client->append_size);
		if ((client->capabilities & CAP_LITERALPLUS) != 0)
			str_append_c(cmd, '+');
		str_append_c(cmd, '}');

		if (client->append_unfinished) {
			/* continues the last APPEND call */
			str_append(cmd, "\r\n");
			o_stream_send_str(client->output, str_c(cmd));
		} else {
			client->state = STATE_APPEND;
			command_send(client, str_c(cmd), state_callback);
			client->append_unfinished = TRUE;
		}

		if ((client->capabilities & CAP_LITERALPLUS) == 0) {
			/* we'll have to wait for "+" */
			i_stream_skip(source->input, client->append_size);
			return 0;
		}
	} else {
		i_stream_seek(source->input, client->append_offset);
	}

	input = i_stream_create_limit(source->input,
				      source->input->v_offset,
				      client->append_size);
	ret = o_stream_send_istream(client->output, input);
        i_stream_unref(&input);

	if (ret < 0) {
		i_error("APPEND failed: %m");
		return -1;
	}
	client->append_size -= ret;
	client->append_offset += ret;

	if (client->append_size != 0) {
		/* unfinished */
		o_stream_set_flush_pending(client->output, TRUE);
		return 0;
	}

	if ((client->capabilities & CAP_MULTIAPPEND) != 0 &&
	    states[STATE_APPEND].probability_again != 0 &&
	    client->plan_size > 0 && client->plan[0] == STATE_APPEND) {
		/* we want to append another message.
		   do it in the same transaction. */
		return client_send_next_cmd(client);
	}

	client->append_unfinished = FALSE;
	o_stream_send_str(client->output, "\r\n");
	return 0;
}

static int client_handle_cmd_reply(struct client *client, struct command *cmd,
				   const struct imap_arg *args,
				   enum command_reply reply)
{
	const char *str, *line;
	unsigned int i;

	line = imap_args_to_str(args);
	switch (reply) {
	case REPLY_OK:
		if (cmd->state != STATE_DISCONNECT)
			counters[cmd->state]++;
		break;
	case REPLY_NO:
		switch (cmd->state) {
		case STATE_COPY:
		case STATE_MCREATE:
		case STATE_MDELETE:
			break;
		case STATE_FETCH:
		case STATE_FETCH2:
			/* possibly tried to fetch expunged messages.
			   don't hide all errors though. */
			if (strstr(line, "no longer exist") != NULL) {
				/* Zimbra */
				break;
			}
			if (strstr(line, "No matching messages") != NULL) {
				/* Cyrus */
				break;
			}
		default:
			client_input_error(client, "%s failed",
					   states[cmd->state].name);
			break;
		}
		break;

	case REPLY_BAD:
		client_input_error(client, "%s replied BAD",
				   states[cmd->state].name);
		return -1;
	case REPLY_CONT:
		if (cmd->state == STATE_APPEND)
			break;

		client_input_error(client, "%s: Unexpected continuation",
				   states[cmd->state].name);
		return -1;
	}

	switch (cmd->state) {
	case STATE_AUTHENTICATE:
	case STATE_LOGIN:
		client->login_state = LSTATE_AUTH;
		if (reply != REPLY_OK) {
			/* authentication failed */
			return -1;
		}

		for (i = 0; i < 3 && !stalled; i++) {
			if (array_count(&clients) >= conf.clients_count)
				break;

			client_new(array_count(&clients),
				   client->view->storage->source);
		}
		break;
	case STATE_SELECT:
		client->login_state = LSTATE_SELECTED;
		break;
	case STATE_COPY:
		if (reply == REPLY_NO) {
			const char *arg = args->type == IMAP_ARG_ATOM ?
				IMAP_ARG_STR(args) : NULL;
			if (arg != NULL &&
			    strcasecmp(arg, "[TRYCREATE]") == 0) {
				str = t_strdup_printf("CREATE %s",
						      conf.copy_dest);
				client->state = STATE_COPY;
				command_send(client, str, state_callback);
				break;
			}
			client_input_error(client, "COPY failed");
		}
		break;
	case STATE_APPEND:
		if (reply == REPLY_CONT) {
			/* finish appending */
			if (client_append(client, TRUE) < 0)
				return -1;
			break;
		}
		break;
	case STATE_LOGOUT:
		if (client->login_state != LSTATE_NONAUTH) {
			/* untagged BYE sets state to DISCONNECT, so we
			   shouldn't get here. */
			client_input_error(client, "Server didn't send BYE");
		}
		return -1;
	case STATE_DISCONNECT:
		return -1;
	default:
		break;
	}

	return 0;
}

int client_send_next_cmd(struct client *client)
{
	enum client_state state;
	string_t *cmd;
	const char *str;
	unsigned int i, j, seq1, seq2, count, msgs;

	state = client_eat_first_plan(client);

	msgs = array_count(&client->view->uidmap);
	if (msgs == 0 && states[state].login_state == LSTATE_SELECTED) {
		/* no messages, no point in doing this command */
		return 0;
	}

	client->state = state;
	switch (state) {
	case STATE_AUTHENTICATE:
		command_send(client, "AUTHENTICATE plain", auth_plain_callback);
		break;
	case STATE_LOGIN:
		str = t_strdup_printf("LOGIN \"%s\" \"%s\"",
				      client->username, conf.password);
		command_send(client, str, state_callback);
		break;
	case STATE_LIST:
		//str = t_strdup_printf("LIST \"\" * RETURN (X-STATUS (MESSAGES))");
		str = t_strdup_printf("LIST \"\" *");
		command_send(client, str, state_callback);
		break;
	case STATE_MCREATE:
		if (rand() % 2)
			str = t_strdup_printf("CREATE \"test/%d\"", rand() % 20);
		else
			str = t_strdup_printf("CREATE \"test/%d/%d\"", rand() % 20, rand() % 20);
		command_send(client, str, state_callback);
		break;
	case STATE_MDELETE:
		if (rand() % 2)
			str = t_strdup_printf("DELETE \"test/%d\"", rand() % 20);
		else
			str = t_strdup_printf("DELETE \"test/%d/%d\"", rand() % 20, rand() % 20);
		command_send(client, str, state_callback);
		break;
	case STATE_SELECT:
		if (client->login_state == LSTATE_SELECTED) {
			/* already selected, don't do it agai */
			break;
		}
		str = t_strdup_printf("SELECT \"%s\"", conf.mailbox);
		command_send(client, str, state_callback);
		break;
	case STATE_FETCH: {
		static const char *fields[] = {
			"UID", "FLAGS", "ENVELOPE", "INTERNALDATE",
			"BODY", "BODYSTRUCTURE"
		};
		static const char *header_fields[] = {
			"From", "To", "Cc", "Subject", "References",
			"In-Reply-To", "Message-ID", "Delivered-To"
		};
		if (msgs > 100) {
			seq1 = (rand() % msgs) + 1;
			seq2 = I_MIN(seq1 + 100, msgs);
		} else {
			seq1 = 1;
			seq2 = msgs;
		}
		cmd = t_str_new(512);
		str_printfa(cmd, "FETCH %u:%u (", seq1, seq2);
		for (i = (rand() % 4) + 1; i > 0; i--) {
			if ((rand() % 4) != 0) {
				str_append(cmd, fields[rand() %
						       N_ELEMENTS(fields)]);
			} else {
				str_append(cmd, "BODY.PEEK[HEADER.FIELDS (");
				for (j = (rand() % 4) + 1; j > 0; j--) {
					int idx = rand() %
						N_ELEMENTS(header_fields);
					str_append(cmd, header_fields[idx]);
					if (j != 1)
						str_append_c(cmd, ' ');
				}
				str_append(cmd, ")]");
			}
			if (i != 1)
				str_append_c(cmd, ' ');
		}
		str_append_c(cmd, ')');
		command_send(client, str_c(cmd), state_callback);
		break;
	}
	case STATE_FETCH2:
		str = t_strdup_printf("FETCH %lu (BODY.PEEK[])",
				      (random() % msgs) + 1);
		command_send(client, str, state_callback);
		break;
	case STATE_SEARCH:
		command_send(client, "SEARCH BODY hello", state_callback);
		break;
	case STATE_SORT:
		if ((rand() % 2) == 0)
			command_send(client, "SORT (SUBJECT) US-ASCII ALL", state_callback);
		else
			command_send(client, "SORT (SUBJECT) US-ASCII FLAGGED", state_callback);
		break;
	case STATE_THREAD:
		command_send(client, "THREAD REFERENCES US-ASCII ALL", state_callback);
		break;
	case STATE_COPY:
		i_assert(conf.copy_dest != NULL);

		seq1 = (rand() % msgs) + 1;
		seq2 = (rand() % (msgs - seq1 + 1));
		seq2 = seq1 + I_MIN(seq2, 5);
		str = t_strdup_printf("COPY %u:%u %s",
				      seq1, seq2, conf.copy_dest);
		command_send(client, str, state_callback);
		break;
	case STATE_STORE:
		cmd = t_str_new(512);
		count = rand() % (msgs < 10 ? msgs : I_MIN(msgs/5, 50));
		for (i = 0; i < count; i++)
			str_printfa(cmd, "%u,", (rand() % msgs) + 1);
		if (str_len(cmd) == 0)
			break;

		str_insert(cmd, 0, "STORE ");
		str_truncate(cmd, str_len(cmd) - 1);
		str_append_c(cmd, ' ');
		switch (rand() % 3) {
		case 0:
			str_append_c(cmd, '+');
			break;
		case 1:
			str_append_c(cmd, '-');
			break;
		default:
			break;
		}
		str_append(cmd, "FLAGS");
		if (conf.checkpoint_interval == 0)
			str_append(cmd, ".SILENT");
		str_printfa(cmd, " (%s)",
			    mailbox_view_get_random_flags(client->view));

		command_send(client, str_c(cmd), state_callback);
		break;
	case STATE_STORE_DEL:
		cmd = t_str_new(512);
		if (msgs > conf.message_count_threshold + 5) {
			count = rand() % (msgs - conf.message_count_threshold);
		} else {
			count = rand() % 5;
		}

		for (i = 0; i < count; i++)
			str_printfa(cmd, "%u,", (rand() % msgs) + 1);

		if (!client->view->storage->seen_all_recent &&
		    conf.checkpoint_interval != 0 && msgs > 0) {
			/* expunge everything so we can start checking RECENT
			   counts */
			str_truncate(cmd, 0);
			str_append(cmd, "1:*,");
		}
		if (str_len(cmd) == 0)
			break;

		str_insert(cmd, 0, "STORE ");
		str_truncate(cmd, str_len(cmd) - 1);
		str_append(cmd, " +FLAGS");
		if (conf.checkpoint_interval == 0)
			str_append(cmd, ".SILENT");
		str_append(cmd, " \\Deleted");

		command_send(client, str_c(cmd), state_callback);
		break;
	case STATE_EXPUNGE:
		command_send(client, "EXPUNGE", state_callback);
		break;
	case STATE_APPEND:
		if (msgs >= conf.message_count_threshold)
			break;

		if (client_append(client, FALSE) < 0)
			return -1;
		break;
	case STATE_STATUS:
		str = t_strdup_printf("STATUS \"%s\" (MESSAGES UNSEEN RECENT)",
				      conf.mailbox);
		command_send(client, str, state_callback);
		break;
	case STATE_NOOP:
		command_send(client, "NOOP", state_callback);
		break;
	case STATE_CHECK:
		command_send(client, "CHECK", state_callback);
		break;
	case STATE_LOGOUT:
		command_send(client, "LOGOUT", state_callback);
		break;

	case STATE_BANNER:
	case STATE_DISCONNECT:
	case STATE_DELAY:
	case STATE_CHECKPOINT:
	case STATE_COUNT:
		i_unreached();
	}
	return 0;
}

void state_callback(struct client *client, struct command *cmd,
		    const struct imap_arg *args, enum command_reply reply)
{
	if (client_handle_cmd_reply(client, cmd, args, reply) < 0) {
		client_unref(client);
		return;
	}

	if (client->checkpointing != NULL) {
		/* we're checkpointing */
		if (array_count(&client->commands) > 0)
			return;

		checkpoint_neg(client->view->storage);
		return;
	} else if (client->view->storage->checkpoint != NULL) {
		/* don't do anything until checkpointing is finished */
		return;
	}

	if (client_send_more_commands(client) < 0)
		client_unref(client);
}
