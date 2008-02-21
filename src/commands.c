/* Copyright (C) 2007 Timo Sirainen */

#include "lib.h"
#include "array.h"
#include "ostream.h"

#include "client.h"
#include "commands.h"

struct command *command_send(struct client *client, const char *cmdline,
			     command_callback_t *callback)
{
	struct command *cmd;
	const char *cmd_str;
	char *p;
	unsigned int tag = client->tag_counter++;

	i_assert(!client->append_unfinished);

	cmd = i_new(struct command, 1);
	cmd->cmdline = i_strdup(cmdline);
	cmd->state = client->state;
	cmd->tag = tag;
	cmd->callback = callback;

	cmdline = NULL;
	p = strchr(cmd->cmdline, '\r');
	if (p != NULL && p != cmd->cmdline && p[-1] == '}') {
		/* using a literal */
		if ((client->capabilities & CAP_LITERALPLUS) == 0 &&
		    p[-2] == '+') {
			/* @UNSAFE: using literal+ without server support,
			   change it to a normal literal */
			memmove(p-2, p-1, strlen(p) + 2);
		}
		if (p[-2] != '+') {
			i_fatal("FIXME: Add support for sync literals");
		}
	}

	cmd_str = t_strdup_printf("%u.%u %s\r\n", client->global_id,
				  tag, cmd->cmdline);
	o_stream_send_str(client->output, cmd_str);
	if (client->rawlog_output != NULL)
		client_rawlog_output(client, cmd_str);

	array_append(&client->commands, &cmd, 1);
	client->last_cmd = cmd;
	return cmd;
}

void command_unlink(struct client *client, struct command *cmd)
{
	struct command *const *cmds;
	unsigned int i, count;

	cmds = array_get(&client->commands, &count);
	for (i = 0; i < count; i++) {
		if (cmds[i] == cmd) {
			array_delete(&client->commands, i, 1);
			break;
		}
	}
	i_assert(i < count);

	if (client->last_cmd == cmd)
		client->last_cmd = NULL;
}

void command_free(struct command *cmd)
{
	if (array_is_created(&cmd->seq_range))
		array_free(&cmd->seq_range);
	i_free(cmd->cmdline);
	i_free(cmd);
}

struct command *command_lookup(struct client *client, unsigned int tag)
{
	struct command *const *cmds;
	unsigned int i, count;

	cmds = array_get(&client->commands, &count);
	for (i = 0; i < count; i++) {
		if (cmds[i]->tag == tag)
			return cmds[i];
	}
	return NULL;
}
