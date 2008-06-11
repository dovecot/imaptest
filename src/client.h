#ifndef CLIENT_H
#define CLIENT_H

#include "client-state.h"

struct mailbox_source;
struct imap_arg;

enum imap_capability {
	CAP_LITERALPLUS		= 0x01,
	CAP_MULTIAPPEND		= 0x02,
	CAP_CONDSTORE		= 0x04,
	CAP_QRESYNC		= 0x08
};

struct imap_capability_name {
	const char *name;
	enum imap_capability capability;
};

static const struct imap_capability_name cap_names[] = {
	{ "LITERAL+", CAP_LITERALPLUS },
	{ "MULTIAPPEND", CAP_MULTIAPPEND },
	{ "CONDSTORE", CAP_CONDSTORE },
	{ "QRESYNC", CAP_QRESYNC },

	{ NULL, 0 }
};

struct client {
	int refcount;

        unsigned int idx, global_id;
        unsigned int cur;

	int fd;
	struct istream *input;
	struct ostream *output, *rawlog_output;
	struct imap_parser *parser;
	struct io *io;
	struct timeout *to;
	size_t prev_size;

	enum client_state state;
	enum login_state login_state;
	enum imap_capability capabilities;
	char **capabilities_list;

	/* plan[0] contains always the next state we move to. */
	enum client_state plan[STATE_COUNT];
	unsigned int plan_size;

	const struct imap_arg *cur_args;
	uoff_t append_offset, append_psize, append_vsize_left, append_skip;
	uoff_t literal_left;

	struct search_context *search_ctx;
	struct test_exec_context *test_exec_ctx;

	struct mailbox_view *view;
	struct mailbox_storage *checkpointing;
	ARRAY_DEFINE(commands, struct command *);
	struct command *last_cmd;
	unsigned int tag_counter;

	int (*send_more_commands)(struct client *client);
	int (*handle_untagged)(struct client *, const struct imap_arg *);

        time_t last_io;

	char *username;
	unsigned int delayed:1;
	unsigned int seen_banner:1;
	unsigned int append_unfinished:1;
	unsigned int append_started:1;
	unsigned int try_create_mailbox:1;
	unsigned int postlogin_capability:1;
	unsigned int qresync_enabled:1;
};
ARRAY_DEFINE_TYPE(client, struct client *);

extern int clients_count;
extern unsigned int total_disconnects;
extern ARRAY_TYPE(client) clients;
extern bool stalled, disconnect_clients, no_new_clients;

struct client *client_new(unsigned int idx, struct mailbox_source *source);
bool client_unref(struct client *client, bool reconnect);
void client_disconnect(struct client *client);

void client_delay(struct client *client, unsigned int msecs);
int client_handle_untagged(struct client *client, const struct imap_arg *args);
void client_capability_parse(struct client *client, const char *line);

int client_send_more_commands(struct client *client);

int client_input_error(struct client *client, const char *fmt, ...)
	ATTR_FORMAT(2, 3);
int client_state_error(struct client *client, const char *fmt, ...)
	ATTR_FORMAT(2, 3);
void client_rawlog_output(struct client *client, const char *line);

unsigned int clients_get_random_idx(void);

void clients_init(void);
void clients_deinit(void);

#endif
