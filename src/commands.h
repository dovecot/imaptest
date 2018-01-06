#ifndef COMMANDS_H
#define COMMANDS_H

#include "seq-range-array.h"
#include "client-state.h"

#include <sys/time.h>

enum command_reply {
	REPLY_BAD,
	REPLY_OK,
	REPLY_NO,
	REPLY_CONT
};

struct imap_client;
struct command;

struct command {
	char *cmdline;
	unsigned int cmdline_len; /* in case there are NUL chars */

	enum client_state state;
	unsigned int tag;
	ARRAY_TYPE(seq_range) seq_range;

	command_callback_t *callback;
	struct timeval tv_start;
	struct timeout *delay_to;

	bool expect_bad:1;
	bool compress_on_ok:1; /* IMAP COMPRESS command */
};

struct command *command_send(struct imap_client *client, const char *cmdline,
			     command_callback_t *callback);
struct command *
command_send_binary(struct imap_client *client, const char *cmdline,
		    unsigned int cmdline_len,
		    command_callback_t *callback);

void command_unlink(struct imap_client *client, struct command *cmd);
void command_free(struct command *cmd);

struct command *command_lookup(struct imap_client *client, unsigned int tag);

#endif
