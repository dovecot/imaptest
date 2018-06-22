#ifndef IMAP_CLIENT_H
#define IMAP_CLIENT_H

#include "client.h"

struct imap_arg;

enum imap_capability {
	CAP_LITERALPLUS		= 0x01,
	CAP_MULTIAPPEND		= 0x02,
	CAP_CONDSTORE		= 0x04,
	CAP_QRESYNC		= 0x08,
	CAP_UIDPLUS		= 0x10,
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
	{ "UIDPLUS", CAP_UIDPLUS },

	{ NULL, 0 }
};

struct mailbox_list_entry {
	char *name;
	bool found;
};
typedef void stacked_cmd_t(struct imap_client *client, struct command *cmd);

struct imap_client {
	struct client client;
    stacked_cmd_t *stacked_cmd;

	struct imap_parser *parser;
	enum imap_capability capabilities;
	char **capabilities_list;

	/* plan[0] contains always the next state we move to. */
	enum client_state plan[STATE_COUNT];
	unsigned int plan_size;

	/* LIST reply */
	ARRAY(struct mailbox_list_entry) mailboxes_list;

	const struct imap_arg *cur_args;
	struct istream *append_stream;
	uoff_t literal_left;

	struct search_context *search_ctx;
	struct test_exec_context *test_exec_ctx;

	struct mailbox_storage *storage;
	struct mailbox_view *view;
	struct mailbox_storage *checkpointing;
	ARRAY(struct command *) commands;
	struct command *last_cmd;
	unsigned int tag_counter;

	/* Highest MODSEQ seen in untagged FETCH replies. Tagged reply
	   handler updates highest_modseq based on this and resets to 0. */
	uint64_t highest_untagged_modseq;
	/* non-NULL when SELECTing a mailbox using QRESYNC */
	struct mailbox_offline_cache *qresync_select_cache;
	/* Value of EXISTS reply */
	unsigned int qresync_pending_exists;

	int (*handle_untagged)(struct imap_client *, const struct imap_arg *);

	bool seen_banner:1;
	bool append_unfinished:1;
	bool try_create_mailbox:1;
	bool postlogin_capability:1;
	bool qresync_enabled:1;
	bool append_can_send:1;
	bool seen_bye:1;
	bool idle_wait_cont:1;
	bool idle_done_sent:1;
	bool preauth:1;
	bool uid_fetch_performed:1;
};

static inline struct imap_client *imap_client(struct client *client)
{
	if (client == NULL || client->protocol != CLIENT_PROTOCOL_IMAP)
		return NULL;
	return (struct imap_client *)client;
}

struct imap_client *
imap_client_new(unsigned int idx, struct user *user, struct user_client *uc);

void imap_client_exists(struct imap_client *client, unsigned int msgs);
void imap_client_mailbox_close(struct imap_client *client);
int imap_client_handle_untagged(struct imap_client *client, const struct imap_arg *args);
void imap_client_capability_parse(struct imap_client *client, const char *line);
void imap_client_log_mailbox_view(struct imap_client *client);
void imap_client_mailboxes_list_begin(struct imap_client *client);
void imap_client_mailboxes_list_end(struct imap_client *client);
struct mailbox_list_entry *
imap_client_mailboxes_list_find(struct imap_client *client, const char *name);

int imap_client_input_error(struct imap_client *client, const char *fmt, ...)
	ATTR_FORMAT(2, 3);
int imap_client_input_warn(struct imap_client *client, const char *fmt, ...)
	ATTR_FORMAT(2, 3);
int imap_client_state_error(struct imap_client *client, const char *fmt, ...)
	ATTR_FORMAT(2, 3);

#endif
