/* Copyright (c) 2007-2008 Timo Sirainen */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "istream.h"
#include "ostream.h"
#include "imap-parser.h"
#include "mailbox.h"
#include "client.h"
#include "commands.h"

#include <ctype.h>

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

static bool
ends_with_literal(const char *line, const char *p, unsigned long *num_r)
{
	unsigned long times = 1, num = 0;
	unsigned int len = p-line+1;

	if (len < 3)
		return FALSE;
	if (p[-1] == '\r')
		p--;
	if (p[-1] != '}')
		return FALSE;
	if (p[-2] == '+')
		p--;
	while (&p[-2] != line && i_isdigit(p[-2])) {
		num += (unsigned long)(p[-2]-'0') * times;
		times *= 10;
		p--;
	}
	if (&p[-2] == line || p[-2] != '{')
		return FALSE;
	if (&p[-3] == line || p[-3] != ' ')
		return FALSE;
	*num_r = num;
	return TRUE;
}

static const char *
command_get_cmdline(struct client *client, const char *cmdline)
{
	string_t *str;
	const char *p;
	unsigned long lit_size;

	p = strchr(cmdline, '\n');
	if (p == NULL)
		return cmdline;

	str = t_str_new(128);
	do {
		if (!ends_with_literal(cmdline, p, &lit_size)) {
			/* looks like a broken line? but allow anyway */
			str_append_n(str, cmdline, p-cmdline+1);
			cmdline = p+1;
		} else {
			/* using a literal */
			if ((client->capabilities & CAP_LITERALPLUS) == 0 &&
			    p[-2] == '+') {
				/* using literal+ without server support,
				   change it to a normal literal */
				i_fatal("FIXME: Add support for sync literals");
			} else if ((client->capabilities & CAP_LITERALPLUS) != 0 &&
				   p[-2] != '+') {
				/* for now we always convert to literal+ */
				str_append_n(str, cmdline, p-cmdline-2);
				str_append(str, "+}");
			} else if (p[-2] != '+') {
				i_fatal("FIXME: Add support for sync literals");
			}
			str_append_c(str, '\n');
			cmdline = p+1;

			/* add literal contents without parsing it */
			i_assert(strlen(cmdline) >= lit_size);
			str_append_n(str, cmdline, lit_size);
			cmdline += lit_size;
		}
		p = strchr(cmdline, '\n');
	} while (p != NULL);
	str_append(str, cmdline);
	return str_c(str);
}

struct command *command_send(struct client *client, const char *cmdline,
			     command_callback_t *callback)
{
	struct command *cmd;
	const char *cmd_str, *cmdname, *argp;
	unsigned int tag = client->tag_counter++;

	i_assert(!client->append_unfinished);

	cmd = i_new(struct command, 1);
	T_BEGIN {
		cmd->cmdline = i_strdup(command_get_cmdline(client, cmdline));
	} T_END;
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
			mailbox_view_free(&client->view);
			mailbox_storage_unref(&client->storage);
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

	cmd_str = t_strdup_printf("%u.%u %s\r\n", client->global_id,
				  tag, cmd->cmdline);
	o_stream_send_str(client->output, cmd_str);

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
