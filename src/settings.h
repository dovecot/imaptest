#ifndef SETTINGS_H
#define SETTINGS_H

#include "network.h"

/* host / port where to connect to */
#define HOST "127.0.0.1"
#define PORT 143
/* Username. You can give either a single user, or a number of users in which
   case the username gets randomized at each connection. */
//#define USERNAME_TEMPLATE "u%04d@d%04d.domain.org"
//#define USERNAME_TEMPLATE "cras%d"
#define USERNAME_TEMPLATE getenv("USER")
#define USER_RAND 99
#define DOMAIN_RAND 99
/* Password (for all users) */
#define PASSWORD "pass"
/* Number of simultaneous client connections */
#define CLIENTS_COUNT 10
/* Number of clients to create at startup. After each successful login a new
   client is created. */
#define INIT_CLIENT_COUNT 10
/* Try to keep around this many messages in mailbox (in expunge + append) */
#define MESSAGE_COUNT_THRESHOLD 30
/* Append messages from this mbox file to mailboxes */
#define MBOX_PATH "~/mail/dovecot-crlf"

/* Add random keywords with max. length n */
//#define RAND_KEYWORDS 40

#define DELAY_MSECS 1000
#define MAX_COMMAND_QUEUE_LEN 10
#define MAX_INLINE_LITERAL_SIZE (1024*32)

struct settings {
	const char *host, *username_template, *password, *mbox_path;
	const char *mailbox, *copy_dest;
	unsigned int port;

	unsigned int clients_count;
	unsigned int message_count_threshold;
	unsigned int checkpoint_interval;

	bool random_states, no_pipelining, disconnect_quit;
	bool no_tracking, rawlog, error_quit, own_flags;

	struct ip_addr ip;
};

extern struct settings conf;

#endif
