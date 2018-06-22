/* Copyright (c) 2007-2018 ImapTest authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "istream.h"
#include "ostream.h"
#include "imap-parser.h"
#include "mailbox.h"
#include "imap-client.h"
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
ends_with_literal(const unsigned char *line, const unsigned char *p,
		  unsigned long *num_r)
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
	if (&p[-3] != line && p[-3] == '~')
		p--;
	if (p[-3] != ' ')
		return FALSE;
	*num_r = num;
	return TRUE;
}

static void
command_get_cmdline(struct imap_client *client, const char **_cmdline,
		    unsigned int *_cmdline_len)
{
	const unsigned char *cmdline = (const void *)*_cmdline;
	unsigned int cmdline_len = *_cmdline_len;
	string_t *str;
	const unsigned char *p;
	unsigned long len, lit_size;

	p = memchr(cmdline, '\n', cmdline_len);
	if (p == NULL)
		return;

	str = t_str_new(128);
	do {
		len = p-cmdline+1;
		if (!ends_with_literal(cmdline, p, &lit_size)) {
			/* looks like a broken line? but allow anyway */
			buffer_append(str, cmdline, len);
			cmdline += len;
			cmdline_len -= len;
		} else {
			/* using a literal */
			if (p[-1] == '\r') {
				p--;
			}
			i_assert(p[-1] == '}');
			if ((client->capabilities & CAP_LITERALPLUS) == 0 &&
			    p[-2] == '+') {
				/* using literal+ without server support,
				   change it to a normal literal */
				i_fatal("FIXME: Add support for sync literals");
			} else if ((client->capabilities & CAP_LITERALPLUS) != 0 &&
				   p[-2] != '+') {
				/* for now we always convert to literal+ */
				buffer_append(str, cmdline, p-cmdline-1);
				str_append(str, "+}");
			} else if (p[-2] != '+') {
				i_fatal("FIXME: Add support for sync literals");
			} else {
				buffer_append(str, cmdline, p-cmdline);
			}
			str_append(str, "\r\n");
			cmdline += len;
			cmdline_len -= len;

			/* add literal contents without parsing it */
			i_assert(cmdline_len >= lit_size);
			buffer_append(str, cmdline, lit_size);
			cmdline += lit_size;
			cmdline_len -= lit_size;
		}
		p = memchr(cmdline, '\n', cmdline_len);
	} while (p != NULL);
	buffer_append(str, cmdline, cmdline_len);

	*_cmdline = str_c(str);
	*_cmdline_len = str_len(str);
}

struct command *command_send_with_param(struct imap_client *client, const char *cmdline,
           command_callback_t *callback, void *cb_param)
{
  return command_send_binary(client, cmdline, strlen(cmdline), callback, cb_param);
}

struct command *command_send(struct imap_client *client, const char *cmdline, command_callback_t *callback) {
  return command_send_binary(client, cmdline, strlen(cmdline), callback, NULL);
}

struct command *
command_send_binary(struct imap_client *client, const char *cmdline,
		    unsigned int cmdline_len,
                    command_callback_t *callback, void *cb_param)
{
	struct command *cmd;
	struct const_iovec iov[3];
	const char *prefix, *cmdname, *argp;
	unsigned int tag = client->tag_counter++;

	i_assert(!client->append_unfinished);

	if (client->client.idling && !client->idle_done_sent) {
		client->idle_done_sent = TRUE;
		o_stream_nsend_str(client->client.output, "DONE\r\n");
	}

	cmd = i_new(struct command, 1);
	T_BEGIN {
		command_get_cmdline(client, &cmdline, &cmdline_len);
		cmd->cmdline = i_malloc(cmdline_len+1);
		memcpy(cmd->cmdline, cmdline, cmdline_len);
		cmd->cmdline_len = cmdline_len;
	} T_END;
    cmd->cb_param = cb_param;
	cmd->state = client->client.state;
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
				client->client.user->username, name);
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
							 client->client.user->username,
							 name);
			if (storage != NULL)
				mailbox_storage_reset(storage);
		}
	}

	prefix = t_strdup_printf("%u.%u ", client->client.global_id, tag);
	iov[0].iov_base = prefix;
	iov[0].iov_len = strlen(prefix);
	iov[1].iov_base = cmd->cmdline;
	iov[1].iov_len = cmd->cmdline_len;
	iov[2].iov_base = "\r\n";
	iov[2].iov_len = 2;
	o_stream_nsendv(client->client.output, iov, 3);
	gettimeofday(&cmd->tv_start, NULL);

	array_append(&client->commands, &cmd, 1);
	client->last_cmd = cmd;
	return cmd;
}

void command_unlink(struct imap_client *client, struct command *cmd)
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

	client_state_add_to_timer(cmd->state, &cmd->tv_start);
	if (client->last_cmd == cmd)
		client->last_cmd = NULL;
}

void command_free(struct command *cmd)
{
	if (array_is_created(&cmd->seq_range))
		array_free(&cmd->seq_range);
	i_free(cmd->cmdline);
    if (cmd->cb_param != NULL) {
      i_free(cmd->cb_param);
    }
	i_free(cmd);
}

struct command *command_lookup(struct imap_client *client, unsigned int tag)
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
