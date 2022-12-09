#ifndef POP3_CLIENT_H
#define POP3_CLIENT_H

#include "client.h"

struct pop3_client;
struct pop3_command;

/* Returns 1 if command is finished, 0 if more data is expected, -1 on error. */
typedef int
pop3_command_callback_t(struct pop3_client *client, struct pop3_command *cmd,
			const char *line);

struct pop3_command {
	char *cmdline;
	enum client_state state;

	pop3_command_callback_t *callback;
	struct timeval tv_start;
};

struct pop3_client {
	struct client client;
	const char *cur_line;
	const char *mech;
	struct dsasl_client *sasl_client;
	ARRAY(struct pop3_command *) commands;

	pool_t uidls_pool;
	ARRAY_TYPE(const_string) uidls;
	unsigned int prev_seq;

	bool seen_banner:1;
	bool auth_reply_sent:1;
	bool retr_reading:1;
	bool uidls_matched:1;
	bool pop3_keep_mails:1;
};

static inline struct pop3_client *pop3_client(struct client *client)
{
	if (client == NULL || client->protocol != CLIENT_PROTOCOL_POP3)
		return NULL;
	return (struct pop3_client *)client;
}

struct pop3_client *
pop3_client_new(unsigned int idx, struct user *user, struct user_client *uc);

int pop3_client_input_error(struct pop3_client *client, const char *fmt, ...)
	ATTR_FORMAT(2, 3);

#endif
