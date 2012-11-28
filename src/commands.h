#ifndef COMMANDS_H
#define COMMANDS_H

#include "seq-range-array.h"
#include "client-state.h"

enum command_reply {
	REPLY_BAD,
	REPLY_OK,
	REPLY_NO,
	REPLY_CONT
};

struct client;
struct command;

struct command {
	char *cmdline;
	unsigned int cmdline_len; /* in case there are NUL chars */

	enum client_state state;
	unsigned int tag;
	ARRAY_TYPE(seq_range) seq_range;

	command_callback_t *callback;

	unsigned int expect_bad:1;
};

struct command *command_send(struct client *client, const char *cmdline,
			     command_callback_t *callback);
struct command *
command_send_binary(struct client *client, const char *cmdline,
		    unsigned int cmdline_len,
		    command_callback_t *callback);

void command_unlink(struct client *client, struct command *cmd);
void command_free(struct command *cmd);

struct command *command_lookup(struct client *client, unsigned int tag);

#endif
