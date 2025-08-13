#ifndef SETTINGS_H
#define SETTINGS_H

#include "net.h"
#include "iostream-ssl.h"

/* host / port where to connect to */
#define HOST "127.0.0.1"
#define PORT 0
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
#define INIT_CLIENT_COUNT 100
/* Try to keep around this many messages in mailbox (in expunge + append) */
#define MESSAGE_COUNT_THRESHOLD 30
/* Append messages from this mbox file to mailboxes */
#define MBOX_PATH "~/mail/dovecot-crlf"
/* FIXME: we should just look this up with LIST "" "" */
#define IMAP_HIERARCHY_SEP '/'

/* Add random keywords with max. length n */
//#define RAND_KEYWORDS 40

#define DELAY_MSECS 1000
#define MAX_COMMAND_QUEUE_LEN 10
#define MAX_INLINE_LITERAL_SIZE (1024*32)

struct settings {
	const char *username_template, *username2_template;
	const char *host, *master_user, *password;
	const char *mailbox, *copy_dest, *mbox_path;
	const char *mech;
	unsigned int port;

	ARRAY_TYPE(const_string) usernames;

	unsigned int clients_count;
	unsigned int message_count_threshold;
	unsigned int checkpoint_interval;
	unsigned int random_msg_size;
	unsigned int stalled_disconnect_timeout;

	unsigned int users_rand_start, users_rand_count;
	unsigned int domains_rand_start, domains_rand_count;

	bool random_states, no_pipelining, disconnect_quit;
	bool no_tracking, rawlog, error_quit, own_msgs, own_flags, qresync,
	     imap4rev2;

	struct ip_addr *ips;
	unsigned int ip_idx, ips_count;

	bool ssl;
	struct ssl_iostream_settings ssl_set;
};

extern struct settings conf;
extern bool profile_running;

void error_quit(void);

#endif
