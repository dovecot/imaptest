#ifndef COMMANDS_H
#define COMMANDS_H

#include "client-state.h"

enum command_reply {
	REPLY_BAD,
	REPLY_OK,
	REPLY_NO,
	REPLY_CONT
};

struct client;
struct command;

typedef void command_callback_t(struct client *client, struct command *cmd,
				const struct imap_arg *args,
				enum command_reply reply);

struct command {
	char *cmdline;
	enum client_state state;
	unsigned int tag;
	command_callback_t *callback;
};

void command_send(struct client *client, const char *cmdline,
		  command_callback_t *callback);

void command_unlink(struct client *client, struct command *cmd);
void command_free(struct command *cmd);

struct command *command_lookup(struct client *client, unsigned int tag);

#endif
