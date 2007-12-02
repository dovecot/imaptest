/* Copyright (C) 2007 Timo Sirainen */

#include "lib.h"
#include "array.h"
#include "ostream.h"

#include "client.h"
#include "commands.h"

void command_send(struct client *client, const char *cmdline,
		  command_callback_t *callback)
{
	struct command *cmd;
	const char *cmd_str;
	unsigned int tag = client->tag_counter++;

	i_assert(!client->append_unfinished);

	cmd = i_new(struct command, 1);
	cmd->cmdline = i_strdup(cmdline);
	cmd->state = client->state;
	cmd->tag = tag;
	cmd->callback = callback;

	cmd_str = t_strdup_printf("%u.%u %s\r\n", client->global_id,
				  tag, cmdline);
	o_stream_send_str(client->output, cmd_str);
	if (client->rawlog_output != NULL) {
		if (!client->rawlog_last_lf)
			o_stream_send_str(client->rawlog_output, "<<<\n");
		o_stream_send_str(client->rawlog_output, cmd_str);
		client->rawlog_last_lf = TRUE;
	}

	array_append(&client->commands, &cmd, 1);
	client->last_cmd = cmd;
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
