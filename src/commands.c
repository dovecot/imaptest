/* Copyright (c) 2007-2008 Timo Sirainen */

#include "lib.h"
#include "array.h"
#include "istream.h"
#include "ostream.h"
#include "imap-parser.h"

#include "mailbox.h"
#include "client.h"
#include "commands.h"

static const char *get_astring(const char *str)
{
	struct imap_parser *parser;
	struct istream *input;
	const struct imap_arg *args;
	const char *ret = NULL;

	input = i_stream_create_from_data(str, strlen(str));
	parser = imap_parser_create(input, NULL, (size_t)-1);
	if (imap_parser_finish_line(parser, 1, 0, &args) > 0 &&
	    imap_arg_get_astring(&args[0], &ret))
		ret = t_strdup(ret);
	imap_parser_unref(&parser);
	i_stream_unref(&input);
	return ret;
}

struct command *command_send(struct client *client, const char *cmdline,
			     command_callback_t *callback)
{
	struct command *cmd;
	const char *cmd_str, *cmdname, *argp;
	char *p;
	unsigned int tag = client->tag_counter++;

	i_assert(!client->append_unfinished);

	cmd = i_new(struct command, 1);
	cmd->cmdline = i_malloc(strlen(cmdline) + 2);
	strcpy(cmd->cmdline, cmdline);
	cmd->state = client->state;
	cmd->tag = tag;
	cmd->callback = callback;

	argp = strchr(cmdline, ' ');
	if (argp == NULL)
		cmdname = cmdline;
	else
		cmdname = t_strdup_until(cmdline, argp++);
	if (argp == NULL) {
		/* error probably */
	} else if (strcasecmp(cmdname, "SELECT") == 0 ||
		   strcasecmp(cmdname, "EXAMINE") == 0) {
		/* switch selected mailbox storage */
		struct mailbox_source *source = client->storage->source;
		const char *name;

		name = get_astring(argp);
		if (name != NULL && strcmp(name, client->storage->name) != 0) {
			mailbox_storage_unref(&client->storage);
			mailbox_view_free(&client->view);
			client->storage = mailbox_storage_get(source,
							      client->username,
							      name);
			client->view = mailbox_view_new(client->storage);
		}
	} else if (strcasecmp(cmdname, "DELETE") == 0 ||
		   strcasecmp(cmdname, "RENAME") == 0) {
		/* clear selected mailbox storage's state,
		   if we're deleting/renaming it */
		struct mailbox_storage *storage;
		const char *name;

		name = get_astring(argp);
		if (name != NULL) {
			storage = mailbox_storage_lookup(client->storage->source,
							 client->username, name);
			if (storage != NULL)
				mailbox_storage_reset(storage);
		}
	}

	cmdline = NULL;
	p = strchr(cmd->cmdline, '\r');
	if (p != NULL && p != cmd->cmdline && p[-1] == '}') {
		/* using a literal */
		if ((client->capabilities & CAP_LITERALPLUS) == 0 &&
		    p[-2] == '+') {
			/* @UNSAFE: using literal+ without server support,
			   change it to a normal literal */
			memmove(p-2, p-1, strlen(p) + 2);
		} else if ((client->capabilities & CAP_LITERALPLUS) != 0 &&
			   p[-2] != '+') {
			/* FIXME: @UNSAFE: for now we always convert to
			   literal+ */
			memmove(p, p-1, strlen(p) + 2);
			p[-1] = '+';
			p++;
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
