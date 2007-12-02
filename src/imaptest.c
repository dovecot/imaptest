/*
   Place this file to compiled Dovecot v1.1 sources' root directory and run:

   gcc imaptest.c -o imaptest -g -Wall -W -I. -Isrc/lib-mail -Isrc/lib -Isrc/lib-imap -Isrc/lib-storage/index/mbox -DHAVE_CONFIG_H src/lib-storage/index/mbox/mbox-from.o src/lib-imap/libimap.a src/lib-mail/libmail.a src/lib/liblib.a

   NOTE: Requires Dovecot v1.1 sources, doesn't compile with Dovecot v1.0.
*/
#include "lib.h"
#include "lib-signals.h"
#include "array.h"
#include "base64.h"
#include "bsearch-insert-pos.h"
#include "buffer.h"
#include "hash.h"
#include "str.h"
#include "strescape.h"
#include "network.h"
#include "istream.h"
#include "ostream.h"
#include "home-expand.h"
#include "seq-range-array.h"

#include "mail-types.h"
#include "message-size.h"
#include "message-header-parser.h"
#include "imap-parser.h"
#include "imap-date.h"
#include "imap-util.h"
#include "src/lib-storage/index/mbox/mbox-from.h"

#define IMAP_PARSE_FLAG_ATOM_ALLCHARS 0 /* FIXME: remove after beta10 */

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>

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

#define DELAY 1000
#define MAX_COMMAND_QUEUE_LEN 10
#define MAX_INLINE_LITERAL_SIZE (1024*32)

struct {
	const char *host, *username_template, *password, *mbox_path;
	const char *mailbox, *copy_dest;
	unsigned int port;

	unsigned int clients_count;
	unsigned int message_count_threshold;
	unsigned int checkpoint_interval;

	bool random_states, no_pipelining, disconnect_quit;
	bool no_tracking, rawlog;

	struct ip_addr ip;
} conf;

enum imap_capability {
	CAP_LITERALPLUS		= 0x01,
	CAP_MULTIAPPEND		= 0x02
};

struct imap_capability_name {
	const char *name;
	enum imap_capability capability;
};

static const struct imap_capability_name cap_names[] = {
	{ "LITERAL+", CAP_LITERALPLUS },
	{ "MULTIAPPEND", CAP_MULTIAPPEND },

	{ NULL, 0 }
};

enum client_state {
	STATE_BANNER,
	STATE_AUTHENTICATE,
	STATE_LOGIN,
	STATE_LIST,
	STATE_MCREATE,
	STATE_MDELETE,
        STATE_STATUS,
	STATE_SELECT,
	STATE_FETCH,
	STATE_FETCH2,
	STATE_SEARCH,
	STATE_SORT,
	STATE_THREAD,
	STATE_COPY,
	STATE_STORE,
	STATE_STORE_DEL,
	STATE_EXPUNGE,
	STATE_APPEND,
        STATE_NOOP,
        STATE_CHECK,
        STATE_LOGOUT,
        STATE_DISCONNECT,
        STATE_DELAY,
        STATE_CHECKPOINT,

        STATE_COUNT
};

enum login_state {
	LSTATE_NONAUTH,
	LSTATE_AUTH,
	LSTATE_SELECTED
};

enum state_flags {
	FLAG_MSGSET			= 0x01,
	FLAG_EXPUNGES			= 0x02,
	FLAG_STATECHANGE		= 0x04,
	FLAG_STATECHANGE_NONAUTH	= 0x08,
	FLAG_STATECHANGE_AUTH		= 0x10,
	FLAG_STATECHANGE_SELECTED	= 0x20
};

struct state {
	const char *name;
	const char *short_name;
	enum login_state login_state;
	int probability;
	int probability_again;
	enum state_flags flags;
};

static struct state states[STATE_COUNT] = {
	{ "BANNER",	  "Bann", LSTATE_NONAUTH,  0,   0,  0 },
	{ "AUTHENTICATE", "Auth", LSTATE_NONAUTH,  0,   0,  FLAG_STATECHANGE | FLAG_STATECHANGE_AUTH },
	{ "LOGIN",	  "Logi", LSTATE_NONAUTH,  100, 0,  FLAG_STATECHANGE | FLAG_STATECHANGE_AUTH },
	{ "LIST",	  "List", LSTATE_AUTH,     50,  0,  FLAG_EXPUNGES },
	{ "MCREATE",	  "MCre", LSTATE_AUTH,     0,   0,  FLAG_EXPUNGES },
	{ "MDELETE",	  "MDel", LSTATE_AUTH,     0,   0,  FLAG_EXPUNGES },
	{ "STATUS",	  "Stat", LSTATE_AUTH,     50,  0,  FLAG_EXPUNGES },
	{ "SELECT",	  "Sele", LSTATE_AUTH,     100, 0,  FLAG_STATECHANGE | FLAG_STATECHANGE_SELECTED },
	{ "FETCH",	  "Fetc", LSTATE_SELECTED, 100, 0,  FLAG_MSGSET },
	{ "FETCH2",	  "Fet2", LSTATE_SELECTED, 100, 30, FLAG_MSGSET },
	{ "SEARCH",	  "Sear", LSTATE_SELECTED, 0,   0,  0 },
	{ "SORT",	  "Sort", LSTATE_SELECTED, 0,   0,  0 },
	{ "THREAD",	  "Thre", LSTATE_SELECTED, 0,   0,  0 },
	{ "COPY",	  "Copy", LSTATE_SELECTED, 33,  5,  FLAG_MSGSET | FLAG_EXPUNGES },
	{ "STORE",	  "Stor", LSTATE_SELECTED, 50,  0,  FLAG_MSGSET },
	{ "DELETE",	  "Dele", LSTATE_SELECTED, 100, 0,  FLAG_MSGSET },
	{ "EXPUNGE",	  "Expu", LSTATE_SELECTED, 100, 0,  FLAG_EXPUNGES },
	{ "APPEND",	  "Appe", LSTATE_AUTH,     100, 5,  FLAG_EXPUNGES },
	{ "NOOP",	  "Noop", LSTATE_AUTH,     0,   0,  FLAG_EXPUNGES },
	{ "CHECK",	  "Chec", LSTATE_AUTH,     0,   0,  FLAG_EXPUNGES },
	{ "LOGOUT",	  "Logo", LSTATE_NONAUTH,  100, 0,  FLAG_STATECHANGE | FLAG_STATECHANGE_NONAUTH },
	{ "DISCONNECT",	  "Disc", LSTATE_NONAUTH,  0,   0,  0 },
	{ "DELAY",	  "Dela", LSTATE_NONAUTH,  0,   0,  0 },
	{ "CHECKPOINT!",  "ChkP", LSTATE_NONAUTH,  0,   0,  0 }
};

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

#define BODY_NIL_REPLY \
	"\"text\" \"plain\" NIL NIL NIL \"7bit\" 0 0 NIL NIL NIL"
#define ENVELOPE_NIL_REPLY \
	"NIL NIL NIL NIL NIL NIL NIL NIL NIL NIL"
#define INTERNALDATE_NIL_TIMESTAMP 0

enum checkpoint_state {
	CHECKPOINT_STATE_NONE,
	CHECKPOINT_STATE_WAIT,
	CHECKPOINT_STATE_CHECK
};

struct message_header {
	const char *name;
	const unsigned char *value;
	unsigned int value_len;
	unsigned int missing:1;
};
ARRAY_DEFINE_TYPE(message_header, struct message_header);

struct message_global {
	char *message_id;
	const char *body, *bodystructure, *envelope;
	const char *virtual_size;

	ARRAY_TYPE(message_header) headers;
};

struct message_metadata_static {
	uint32_t uid;
	unsigned int refcount;

	time_t internaldate;

	struct message_global *msg;
};

struct message_metadata_dynamic {
#define MAIL_FLAGS_SET 0x40000000
	/* flags and keywords are set only if MAIL_FLAGS_SET is set */
	enum mail_flags mail_flags;
	uint8_t *keyword_bitmask; /* [view->keyword_bitmask_alloc_size] */

	struct message_metadata_static *ms;
};

struct mbox_source {
	int fd;
	char *path;
	struct istream *input;
	uoff_t next_offset;

	pool_t messages_pool;
	struct hash_table *messages;
};

struct mailbox_keyword {
	char *name;
	/* number of messages containing this keyword (that we know of) */
	unsigned int refcount;
	unsigned int flags_counter; /* should match view->flags_counter */
};

struct mailbox_storage {
	struct mbox_source *source;

	enum checkpoint_state checkpoint_state;
	unsigned int checkpoint_clients_left;

	/* we assume that uidvalidity doesn't change while imaptest
	   is running */
	unsigned int uidvalidity;

	/* static metadata for this mailbox. sorted by UID. */
	ARRAY_DEFINE(static_metadata, struct message_metadata_static *);

	unsigned int seen_all_recent:1;
	unsigned int dont_track_recent:1;
};

struct mailbox_view {
	struct mailbox_storage *storage;
	unsigned int keyword_bitmask_alloc_size;
	unsigned int flags_counter;
	unsigned int recent_count;
	unsigned int select_uidnext; /* UIDNEXT received on SELECT */

	/* all keywords used currently in a mailbox */
	ARRAY_DEFINE(keywords, struct mailbox_keyword);

	/* seq -> uid */
	ARRAY_DEFINE(uidmap, uint32_t);
	/* seq -> metadata */
	ARRAY_DEFINE(messages, struct message_metadata_dynamic);

	unsigned int keywords_can_create_more:1;
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

	/* plan[0] contains always the next state we move to. */
	enum client_state plan[STATE_COUNT];
	unsigned int plan_size;

	uoff_t append_offset, append_size;
	uoff_t literal_left;

	struct mailbox_view *view;
	struct mailbox_storage *checkpointing;
	ARRAY_DEFINE(commands, struct command *);
	struct command *last_cmd;
	unsigned int tag_counter;

        time_t last_io;

	char *username;
	unsigned int delayed:1;
	unsigned int seen_banner:1;
	unsigned int append_unfinished:1;
	unsigned int rawlog_last_lf:1;
};

static struct ioloop *ioloop;
static unsigned int counters[STATE_COUNT], total_counters[STATE_COUNT];
static time_t next_checkpoint_time;

static int return_value = 0;
static bool stalled = FALSE;
static bool disconnect_clients = FALSE;
static int clients_count = 0;
unsigned int total_disconnects = 0;
static unsigned int global_id_counter = 0;
static ARRAY_DEFINE(clients, struct client *);
static ARRAY_DEFINE(stalled_clients, unsigned int);

static struct mbox_source *mbox_source;
struct mailbox_storage *global_storage = NULL;

static struct client *client_new(unsigned int idx, struct mbox_source *source);
static bool client_unref(struct client *client);

static void client_input(struct client *client);
static void state_callback(struct client *client, struct command *cmd,
			   const struct imap_arg *args,
			   enum command_reply reply);
static int client_send_next_cmd(struct client *client);

static struct mbox_source *mbox_source_open(const char *path)
{
	struct mbox_source *source;

	source = i_new(struct mbox_source, 1);
	source->path = i_strdup(path);
	source->fd = open(path, O_RDONLY);
	if (source->fd == -1)
		i_fatal("open(%s) failed: %m", path);
	source->input = i_stream_create_fd(source->fd, (size_t)-1, FALSE);

	source->messages_pool = pool_alloconly_create("messages", 1024*1024);
	source->messages = hash_create(default_pool, default_pool, 0, str_hash,
				       (hash_cmp_callback_t *)strcmp);
	return source;
}

static void mbox_close(struct mbox_source *source)
{
	hash_destroy(&source->messages);
	pool_unref(&source->messages_pool);
	i_stream_unref(&source->input);
	(void)close(source->fd);
	i_free(source->path);
	i_free(source);
}

static void mbox_get_next_size(struct mbox_source *source, uoff_t *size_r,
			       time_t *time_r)
{
	const char *line;
	char *sender;
	uoff_t offset, last_offset;
	time_t next_time;

	i_stream_seek(source->input, source->next_offset);

	line = i_stream_read_next_line(source->input);
	if (line == NULL) {
		if (source->input->v_offset == 0)
			i_fatal("Empty mbox file: %s", source->path);

		source->next_offset = 0;
		mbox_get_next_size(source, size_r, time_r);
		return;
	}

	/* should be From-line */
	if (strncmp(line, "From ", 5) != 0 ||
	    mbox_from_parse((const unsigned char *)line+5, strlen(line+5),
			    time_r, &sender) < 0) {
		if (source->input->v_offset == 0)
			i_fatal("Not a valid mbox file: %s", source->path);
		i_panic("From-line not found at %"PRIuUOFF_T,
			source->input->v_offset);
	}
	i_free(sender);

        offset = last_offset = source->input->v_offset;
        while ((line = i_stream_read_next_line(source->input)) != NULL) {
		if (strncmp(line, "From ", 5) == 0 &&
		    mbox_from_parse((const unsigned char *)line+5,
				    strlen(line+5), &next_time, &sender) == 0) {
			i_free(sender);
			if (offset != last_offset)
                                break;

                        /* empty body */
                        offset = last_offset;
                }
                last_offset = source->input->v_offset;
        }
        if (offset == last_offset)
                i_fatal("mbox file ends with From-line: %s", source->path);

        *size_r = last_offset - offset;
	i_stream_seek(source->input, offset);

	source->next_offset = last_offset;
}

static void
imap_args_to_str_dest(const struct imap_arg *args, string_t *str)
{
	const ARRAY_TYPE(imap_arg_list) *list;
	bool first = TRUE;

	for (; args->type != IMAP_ARG_EOL; args++) {
		if (first)
			first = FALSE;
		else
			str_append_c(str, ' ');

		switch (args->type) {
		case IMAP_ARG_NIL:
			str_append(str, "NIL");
			break;
		case IMAP_ARG_ATOM:
			str_append(str, IMAP_ARG_STR(args));
			break;
		case IMAP_ARG_STRING:
			str_append_c(str, '"');
			str_append(str, str_escape(IMAP_ARG_STR(args)));
			str_append_c(str, '"');
			break;
		case IMAP_ARG_LITERAL: {
			const char *strarg = IMAP_ARG_STR(args);
			str_printfa(str, "{%"PRIuSIZE_T"}\r\n", strlen(strarg));
			str_append(str, strarg);
			break;
		}
		case IMAP_ARG_LIST:
			str_append_c(str, '(');
			list = IMAP_ARG_LIST(args);
			imap_args_to_str_dest(array_idx(list, 0), str);
			str_append_c(str, ')');
			break;
		case IMAP_ARG_LITERAL_SIZE:
		case IMAP_ARG_LITERAL_SIZE_NONSYNC:
		case IMAP_ARG_EOL:
			i_unreached();
		}
	}
}

static const char *imap_args_to_str(const struct imap_arg *args)
{
	string_t *str;

	if (args == NULL)
		return "";

	str = t_str_new(256);
	imap_args_to_str_dest(args, str);
	return str_c(str);
}

static int client_input_error(struct client *client,
			      const struct imap_arg *args,
			      const char *fmt, ...) ATTR_FORMAT(3, 4);
static int client_input_error(struct client *client,
			      const struct imap_arg *args,
			      const char *fmt, ...)
{
	va_list va;

	va_start(va, fmt);
	i_error("%s[%u]: %s: %s", client->username, client->global_id,
		t_strdup_vprintf(fmt, va), imap_args_to_str(args));
	va_end(va);

	i_stream_close(client->input);
	o_stream_close(client->output);
	return -1;
}

static void client_exists(struct client *client, unsigned int msgs)
{
	unsigned int old_count = array_count(&client->view->uidmap);

	if (msgs < old_count) {
		i_error("%s: Message count dropped %u -> %u",
			client->username, old_count, msgs);
		array_delete(&client->view->uidmap, msgs, old_count - msgs);
		return;
	}
	for (; old_count < msgs; old_count++)
		(void)array_append_space(&client->view->uidmap);
}

static void
mailbox_keywords_drop(struct mailbox_view *view, const uint8_t *bitmask)
{
	struct mailbox_keyword *keywords;
	unsigned int i, count;

	keywords = array_get_modifiable(&view->keywords, &count);
	for (i = 0; i < count; i++) {
		if ((bitmask[i/8] & (1 << (i%8))) != 0) {
			i_assert(keywords[i].refcount > 0);
			keywords[i].refcount--;
		}
	}
}

static int metadata_static_cmp(const void *key, const void *data)
{
	const uint32_t *uidp = key;
	const struct message_metadata_static *const *ms = data;

	return *uidp < (*ms)->uid ? -1 :
		(*uidp > (*ms)->uid ? 1 : 0);
}

static struct message_metadata_static *
message_metadata_static_get(struct mailbox_storage *storage, uint32_t uid)
{
	struct message_metadata_static **base, *ms;
	unsigned int count, idx;

	base = array_get_modifiable(&storage->static_metadata, &count);
	if (bsearch_insert_pos(&uid, base, count, sizeof(*base),
			       metadata_static_cmp, &idx)) {
		base[idx]->refcount++;
		return base[idx];
	}

	ms = i_new(struct message_metadata_static, 1);
	ms->uid = uid;
	ms->refcount = 1;
	array_insert(&storage->static_metadata, idx, &ms, 1);

	base = array_get_modifiable(&storage->static_metadata, &count);
	return base[idx];
}

static void message_metadata_static_unref(struct mailbox_storage *storage,
					  struct message_metadata_static **_ms)
{
	struct message_metadata_static *ms = *_ms;
	struct message_metadata_static **base;
	unsigned int count, idx;

	*_ms = NULL;
	i_assert(ms->refcount > 0);
	if (--ms->refcount > 0)
		return;

	base = array_get_modifiable(&storage->static_metadata, &count);
	if (!bsearch_insert_pos(&ms->uid, base, count, sizeof(*base),
				metadata_static_cmp, &idx))
		i_unreached();
	else
		array_delete(&storage->static_metadata, idx, 1);
	i_free(ms);
}

static void mailbox_expunge(struct mailbox_view *view, unsigned int seq)
{
	struct message_metadata_dynamic *metadata;

	metadata = array_idx_modifiable(&view->messages, seq - 1);
	i_free(metadata->keyword_bitmask);
	if (metadata->keyword_bitmask != NULL)
		mailbox_keywords_drop(view, metadata->keyword_bitmask);
	if (metadata->ms != NULL)
		message_metadata_static_unref(view->storage, &metadata->ms);
	array_delete(&view->uidmap, seq - 1, 1);
	array_delete(&view->messages, seq - 1, 1);

	if (array_count(&view->uidmap) == 0)
		view->storage->seen_all_recent = TRUE;
}

static void
client_fetch_envelope(struct client *client,
		      struct message_metadata_dynamic *metadata,
		      const struct imap_arg *args, uint32_t uid)
{
	const ARRAY_TYPE(imap_arg_list) *list;
	const char *message_id;
	struct message_global *msg;
	pool_t pool = client->view->storage->source->messages_pool;

	list = IMAP_ARG_LIST(args);
	args = array_idx(list, 0);
	message_id = args[9].type != IMAP_ARG_STRING ? NULL :
		IMAP_ARG_STR(&args[9]);

	if (message_id == NULL)
		return;

	if (metadata->ms->msg != NULL) {
		if (strcmp(metadata->ms->msg->message_id, message_id) == 0)
			return;

		client_input_error(client, args,
			"UID %u changed Message-Id: %s -> %s",
			uid, metadata->ms->msg->message_id, message_id);
		return;
	}

	msg = hash_lookup(client->view->storage->source->messages, message_id);
	if (msg != NULL) {
		metadata->ms->msg = msg;
		return;
	}

	/* new message */
	metadata->ms->msg = msg = p_new(pool, struct message_global, 1);
	msg->message_id = p_strdup(pool, message_id);
	hash_insert(client->view->storage->source->messages,
		    msg->message_id, msg);
}

static const struct imap_arg *
fetch_list_get(const struct imap_arg *list_arg, const char *name)
{
	const ARRAY_TYPE(imap_arg_list) *list;
	const struct imap_arg *args;
	const char *str;
	unsigned int i, count;

	list = IMAP_ARG_LIST(list_arg);
	args = array_get(list, &count);
	for (i = 0; i+1 < count; i += 2) {
		if (args[i].type != IMAP_ARG_ATOM)
			continue;

		str = IMAP_ARG_STR(&args[i]);
		if (strcasecmp(name, str) == 0)
			return &args[i+1];
	}
	return NULL;
}

static enum mail_flags mail_flag_parse(const char *str)
{
	switch (i_toupper(*str)) {
	case 'A':
		if (strcasecmp(str, "ANSWERED") == 0)
			return MAIL_ANSWERED;
		break;
	case 'D':
		if (strcasecmp(str, "DELETED") == 0)
			return MAIL_DELETED;
		if (strcasecmp(str, "DRAFT") == 0)
			return MAIL_DRAFT;
		break;
	case 'F':
		if (strcasecmp(str, "FLAGGED") == 0)
			return MAIL_FLAGGED;
		break;
	case 'R':
		if (strcasecmp(str, "RECENT") == 0)
			return MAIL_RECENT;
		break;
	case 'S':
		if (strcasecmp(str, "SEEN") == 0)
			return MAIL_SEEN;
		break;
	}
	return 0;
}

static struct mailbox_keyword *
mailbox_keyword_get(struct mailbox_view *view, unsigned int idx)
{
	i_assert(idx < array_count(&view->keywords));
	return array_idx_modifiable(&view->keywords, idx);
}

static void mailbox_keyword_add(struct mailbox_view *view, const char *name)
{
	struct mailbox_keyword keyword;

	memset(&keyword, 0, sizeof(keyword));
	keyword.name = i_strdup(name);
	keyword.flags_counter = view->flags_counter;
	array_append(&view->keywords, &keyword, 1);
}

static bool mailbox_keyword_find(struct mailbox_view *view, const char *name,
				 unsigned int *idx_r)
{
	const struct mailbox_keyword *keywords;
	unsigned int i, count;

	keywords = array_get(&view->keywords, &count);
	for (i = 0; i < count; i++) {
		if (strcasecmp(keywords[i].name, name) == 0) {
			*idx_r = i;
			return TRUE;
		}
	}
	return FALSE;
}

static void
message_metadata_set_flags(struct client *client, const struct imap_arg *args,
			   struct message_metadata_dynamic *metadata)
{
	struct mailbox_view *view = client->view;
	struct mailbox_keyword *kw;
	enum mail_flags flag, flags = 0;
	unsigned int idx;
	const char *atom;

	if (view->keyword_bitmask_alloc_size > 0) {
		if (metadata->keyword_bitmask == NULL) {
			metadata->keyword_bitmask =
				i_malloc(view->keyword_bitmask_alloc_size);
		} else {
			mailbox_keywords_drop(view,
					      metadata->keyword_bitmask);
		}
		memset(metadata->keyword_bitmask, 0,
		       view->keyword_bitmask_alloc_size);
	}

	while (args->type != IMAP_ARG_EOL) {
		if (args->type != IMAP_ARG_ATOM) {
			client_input_error(client, args,
				"Flags list contains non-atoms.");
			return;
		}

		atom = IMAP_ARG_STR(args);
		if (*atom == '\\') {
			/* system flag */
			flag = mail_flag_parse(atom + 1);
			if (flag != 0)
				flags |= flag;
			else {
				client_input_error(client, args,
					"Invalid system flag: %s", atom);
			}
		} else if (!mailbox_keyword_find(view, atom, &idx)) {
			client_input_error(client, args,
				"Keyword used without being in FLAGS: %s",
				atom);
		} else {
			i_assert(idx/8 < view->keyword_bitmask_alloc_size);
			kw = array_idx_modifiable(&view->keywords, idx);
			kw->refcount++;
			metadata->keyword_bitmask[idx/8] |= 1 << (idx % 8);
		}

		args++;
	}
	metadata->mail_flags = flags | MAIL_FLAGS_SET;
}

static void
headers_parse(struct client *client, const struct imap_arg *args,
	      struct istream *input, ARRAY_TYPE(message_header) *headers_arr)
{
	struct message_header_parser_ctx *parser;
	struct message_header_line *hdr;
	struct message_size hdr_size;
	struct message_header *headers;
	unsigned char *new_value;
	unsigned int i, count;
	int ret;

	headers = array_get_modifiable(headers_arr, &count);
	parser = message_parse_header_init(input, &hdr_size, 0);
	while ((ret = message_parse_header_next(parser, &hdr)) > 0) {
		if (hdr->continues) {
			hdr->use_full_value = TRUE;
			continue;
		}

		for (i = 0; i < count; i++) {
			if (strcasecmp(headers[i].name, hdr->name) == 0)
				break;
		}
		if (i == count) {
			client_input_error(client, args,
				"Unexpected header in reply: %s", hdr->name);
		} else if (headers[i].value_len == 0) {
			/* first header */
			new_value = hdr->full_value_len == 0 ? NULL :
				t_malloc(hdr->full_value_len);
			memcpy(new_value, hdr->full_value, hdr->full_value_len);
			headers[i].value = new_value;
			headers[i].value_len = hdr->full_value_len;
			headers[i].missing = FALSE;
		} else {
			/* @UNSAFE: second header. append after first. */
			new_value = t_malloc(headers[i].value_len + 1 +
					     hdr->full_value_len);
			memcpy(new_value, headers[i].value,
			       headers[i].value_len);
			new_value[headers[i].value_len] = '\n';
			memcpy(new_value + 1 + headers[i].value_len,
			       hdr->full_value, hdr->full_value_len);
			headers[i].value = new_value;
			headers[i].value_len += hdr->full_value_len;

		}
	}
	i_assert(ret != 0);

	message_parse_header_deinit(&parser);
}

static void headers_match(struct client *client, const struct imap_arg *args,
			  ARRAY_TYPE(message_header) *headers_arr,
			  struct message_global *msg)
{
	pool_t pool = client->view->storage->source->messages_pool;
	const struct message_header *fetch_headers, *orig_headers;
	struct message_header msg_header;
	unsigned char *value;
	unsigned int i, j, fetch_count, orig_count;

	if (!array_is_created(&msg->headers))
		p_array_init(&msg->headers, pool, 8);

	fetch_headers = array_get_modifiable(headers_arr, &fetch_count);
	orig_headers = array_get(&msg->headers, &orig_count);
	for (i = 0; i < fetch_count; i++) {
		for (j = 0; j < orig_count; j++) {
			if (strcasecmp(fetch_headers[i].name,
				       orig_headers[j].name) == 0)
				break;
		}
		if (j == orig_count) {
			/* first time we've seen this, add it */
			memset(&msg_header, 0, sizeof(msg_header));
			msg_header.name = p_strdup(pool, fetch_headers[i].name);
			msg_header.value_len = fetch_headers[i].value_len;
			msg_header.missing = fetch_headers[i].missing;
			if (msg_header.value_len != 0) {
				value = p_malloc(pool, msg_header.value_len);
				memcpy(value, fetch_headers[i].value,
				       msg_header.value_len);
				msg_header.value = value;
				array_append(&msg->headers, &msg_header, 1);
			}
			orig_headers = array_get(&msg->headers, &orig_count);
		} else if (fetch_headers[i].missing != orig_headers[j].missing ||
			   fetch_headers[i].value_len != orig_headers[j].value_len ||
			   memcmp(fetch_headers[i].value,
				  orig_headers[j].value,
				  fetch_headers[i].value_len) != 0) {
			client_input_error(client, args,
				"%s: Header %s changed '%.*s' -> '%.*s'",
				msg->message_id, fetch_headers[i].name,
				(int)orig_headers[j].value_len,
				(const char *)orig_headers[j].value,
				(int)fetch_headers[i].value_len,
				(const char *)fetch_headers[i].value);
		}
	}
}

static int
fetch_parse_header_fields(struct client *client, const struct imap_arg *args,
			  unsigned int args_idx,
			  struct message_metadata_static *ms)
{
	const ARRAY_TYPE(imap_arg_list) *list;
	const struct imap_arg *header_args, *arg;
	const char *header;
	struct message_header msg_header;
	struct istream *input;
	ARRAY_TYPE(message_header) headers;
	const struct message_header *fetch_headers = NULL;
	unsigned int i, fetch_count = 0;

	t_array_init(&headers, 8);
	list = IMAP_ARG_LIST(&args[args_idx]);
	header_args = array_idx(list, 0);
	for (arg = header_args; arg->type != IMAP_ARG_EOL; arg++) {
		if (arg->type != IMAP_ARG_ATOM && arg->type != IMAP_ARG_STRING)
			return -1;

		memset(&msg_header, 0, sizeof(msg_header));
		msg_header.name = IMAP_ARG_STR(arg);
		msg_header.missing = TRUE;

		/* drop duplicates */
		for (i = 0; i < fetch_count; i++) {
			if (strcasecmp(fetch_headers[i].name,
				       msg_header.name) == 0)
				break;
		}

		if (i == fetch_count) {
			array_append(&headers, &msg_header, 1);
			fetch_headers = array_get(&headers, &fetch_count);
		}
	}
	/* track also the end of headers empty line */
	memset(&msg_header, 0, sizeof(msg_header));
	msg_header.name = "";
	msg_header.missing = TRUE;
	array_append(&headers, &msg_header, 1);

	args_idx++;
	if (args[args_idx].type != IMAP_ARG_ATOM)
		return -1;

	if (strcmp(IMAP_ARG_STR_NONULL(&args[args_idx]), "]") != 0)
		return -1;
	args_idx++;

	if (args[args_idx].type == IMAP_ARG_NIL) {
		/* expunged? */
		return 0;
	}
	if (!IMAP_ARG_TYPE_IS_STRING(args[args_idx].type))
		return -1;

	header = IMAP_ARG_STR(&args[args_idx]);
	if (*header == '\0' && args[args_idx].type == IMAP_ARG_STRING) {
		/* Cyrus: expunged */
		return 0;
	}

	/* parse headers */
	input = i_stream_create_from_data(header, strlen(header));
	headers_parse(client, args, input, &headers);
	i_stream_destroy(&input);

	headers_match(client, args, &headers, ms->msg);
	return 0;
}

static void client_fetch(struct client *client, unsigned int seq,
			 const struct imap_arg *args)
{
	struct mailbox_view *view = client->view;
	struct message_metadata_dynamic *metadata;
	const ARRAY_TYPE(imap_arg_list) *list;
	const struct imap_arg *arg;
	const char *name, *value, **p;
	uint32_t uid, *uidp;
	unsigned int i, list_count;

	uidp = array_idx_modifiable(&view->uidmap, seq-1);

	if (args->type != IMAP_ARG_LIST) {
		client_input_error(client, args, "FETCH didn't return a list");
		return;
	}

	arg = fetch_list_get(args, "UID");
	if (arg != NULL && arg->type == IMAP_ARG_ATOM) {
		value = IMAP_ARG_STR(arg);
		uid = strtoul(value, NULL, 10);
		if (*uidp == 0)
			*uidp = uid;
		else if (*uidp != uid) {
			client_input_error(client, args,
				"UID changed for sequence %u: %u -> %u",
				seq, *uidp, uid);
			*uidp = uid;
		}
	}
	if (*uidp == 0)
		return;
	uid = *uidp;

	metadata = array_idx_modifiable(&view->messages, seq - 1);
	if (metadata->ms == NULL) {
		metadata->ms =
			message_metadata_static_get(client->view->storage, uid);
	}
	i_assert(metadata->ms->uid == uid);

	/* Get Message-ID from envelope if it exists. */
	arg = fetch_list_get(args, "ENVELOPE");
	if (arg != NULL && arg->type == IMAP_ARG_LIST)
		client_fetch_envelope(client, metadata, arg, uid);

	/* the message is known, verify that everything looks ok */
	list = IMAP_ARG_LIST(args);
	args = array_get(list, &list_count);

	t_push();
	for (i = 0; i+1 < list_count; i += 2) {
		if (args[i].type != IMAP_ARG_ATOM)
			continue;

		name = t_str_ucase(IMAP_ARG_STR(&args[i]));
		list = NULL;
		if (IMAP_ARG_TYPE_IS_STRING(args[i+1].type))
			value = IMAP_ARG_STR(&args[i+1]);
		else if (args[i+1].type == IMAP_ARG_LIST) {
			list = IMAP_ARG_LIST(&args[i+1]);
			value = imap_args_to_str(array_idx(list, 0));
		} else
			continue;

		if (strcmp(name, "FLAGS") == 0) {
			if (list == NULL) {
				client_input_error(client, args,
						   "FLAGS reply isn't a list");
				continue;
			}
			message_metadata_set_flags(client, array_idx(list, 0),
						   metadata);
			continue;
		}
		if (strcmp(name, "INTERNALDATE") == 0) {
			time_t t;
			int tz_offset;

			if (!imap_parse_datetime(value, &t, &tz_offset)) {
				client_input_error(client, args,
						   "Broken INTERNALDATE");
			} else if (t == INTERNALDATE_NIL_TIMESTAMP) {
				/* ignore */
			} else if (metadata->ms->internaldate == 0)
				metadata->ms->internaldate = t;
			else if (metadata->ms->internaldate != t) {
				client_input_error(client, args,
					"UID=%u INTERNALDATE changed %s -> %s",
					uid,
					dec2str(metadata->ms->internaldate),
					dec2str(t));
			}
			continue;
		}

		/* next follows metadata that require the message to be known */
		if (metadata->ms->msg == NULL)
			continue;

		if (strcmp(name, "BODY") == 0) {
			if (strncmp(value, BODY_NIL_REPLY,
				    strlen(BODY_NIL_REPLY)) == 0)
				continue;
			p = &metadata->ms->msg->body;
		} else if (strcmp(name, "BODYSTRUCTURE") == 0) {
			if (strncmp(value, BODY_NIL_REPLY,
				    strlen(BODY_NIL_REPLY)) == 0)
				continue;
			p = &metadata->ms->msg->bodystructure;
		} else if (strcmp(name, "ENVELOPE") == 0) {
			if (strncmp(value, ENVELOPE_NIL_REPLY,
				    strlen(ENVELOPE_NIL_REPLY)) == 0)
				continue;
			p = &metadata->ms->msg->envelope;
		} else if (strcmp(name, "RFC822.SIZE") == 0)
			p = &metadata->ms->msg->virtual_size;
		else if (strcmp(name, "BODY[HEADER.FIELDS") == 0) {
			if (fetch_parse_header_fields(client, args, i+1,
						      metadata->ms) < 0) {
				client_input_error(client, args,
						   "Broken HEADER.FIELDS");
			}
			continue;
		} else
			continue;

		if (*p == NULL || strcasecmp(*p, value) != 0) {
			if (*p != NULL) {
				client_input_error(client, args,
					"%s: %s changed '%s' -> '%s'",
					metadata->ms->msg->message_id, name,
					*p, value);
			}
			*p = p_strdup(view->storage->source->messages_pool,
				      value);
		}
	}
	t_pop();
}

static const char *
keywords2str(struct mailbox_view *view, const uint8_t *bitmask)
{
	const struct mailbox_keyword *keywords;
	string_t *str;
	unsigned int i, count;

	keywords = array_get(&view->keywords, &count);
	if (count == 0)
		return "";

	str = t_str_new(128);
	for (i = 0; i < count; i++) {
		if ((bitmask[i/8] & (1 << (i%8))) != 0) {
			if (str_len(str) > 0)
				str_append_c(str, ' ');
			str_append(str, keywords[i].name);
		}
	}
	return str_c(str);
}

static const char *flags2str(enum mail_flags flags)
{
	string_t *str;

	str = t_str_new(40);
	imap_write_flags(str, flags, NULL);
	return str_c(str);
}

static void
mailbox_keywords_realloc(struct mailbox_view *view, unsigned int new_alloc_size)
{
	struct message_metadata_dynamic *metadata;
	unsigned int i, count, old_alloc_size;

	old_alloc_size = view->keyword_bitmask_alloc_size;
	view->keyword_bitmask_alloc_size = new_alloc_size;

	metadata = array_get_modifiable(&view->messages, &count);
	for (i = 0; i < count; i++) {
		metadata->keyword_bitmask =
			i_realloc(metadata->keyword_bitmask,
				  old_alloc_size, new_alloc_size);
	}
}

static void client_set_flags(struct client *client, const struct imap_arg *args)
{
	struct mailbox_view *view = client->view;
	const ARRAY_TYPE(imap_arg_list) *list;
	const struct mailbox_keyword *keywords;
	struct mailbox_keyword *kw;
	unsigned int idx, i, count;
	const char *atom;

	if (args->type != IMAP_ARG_LIST) {
		client_input_error(client, args, "FLAGS doesn't contain list");
		return;
	}
	list = IMAP_ARG_LIST(args);
	args = array_idx(list, 0);

	view->flags_counter++;
	while (args->type != IMAP_ARG_EOL) {
		if (args->type != IMAP_ARG_ATOM) {
			client_input_error(client, args,
				"FLAGS list contains non-atoms.");
			return;
		}

		atom = IMAP_ARG_STR(args);
		if (*atom == '\\') {
			/* system flag */
			if (mail_flag_parse(atom + 1) == 0) {
				client_input_error(client, args,
					"Invalid system flag: %s", atom);
			}
		} else {
			if (!mailbox_keyword_find(view, atom, &idx))
				mailbox_keyword_add(view, atom);
			else {
				kw = mailbox_keyword_get(view, idx);
				kw->flags_counter = view->flags_counter;
			}
		}

		args++;
	}

	keywords = array_get(&view->keywords, &count);
	for (i = 0; i < count; i++) {
		if (keywords[i].flags_counter != view->flags_counter &&
		    keywords[i].refcount > 0) {
			i_error("Keyword '%s' dropped, but it still had "
				"%d references", keywords[i].name,
				keywords[i].refcount);
		}
	}

	if ((count+7)/8 > view->keyword_bitmask_alloc_size)
		mailbox_keywords_realloc(view, (count+7) / 8 * 4);
}

static void
client_set_permanent_flags(struct client *client, const struct imap_arg *args)
{
	const ARRAY_TYPE(imap_arg_list) *list;
	const char *atom;

	if (args->type != IMAP_ARG_LIST) {
		client_input_error(client, args, "FLAGS doesn't contain list");
		return;
	}
	list = IMAP_ARG_LIST(args);
	args = array_idx(list, 0);

	client->view->keywords_can_create_more = FALSE;
	while (args->type != IMAP_ARG_EOL) {
		if (args->type != IMAP_ARG_ATOM) {
			client_input_error(client, args,
				"FLAGS list contains non-atoms.");
			return;
		}

		atom = IMAP_ARG_STR(args);
		if (strcmp(atom, "\\*") == 0)
			client->view->keywords_can_create_more = TRUE;
		args++;
	}
}

static void client_capability_parse(struct client *client, const char *line)
{
	const char *const *tmp;
	unsigned int i;

	client->capabilities = 0;

	for (tmp = t_strsplit(line, " "); *tmp != NULL; tmp++) {
		for (i = 0; cap_names[i].name != NULL; i++) {
			if (strcasecmp(*tmp, cap_names[i].name) == 0) {
				client->capabilities |= cap_names[i].capability;
				break;
			}
		}
	}
}

static int
client_handle_untagged(struct client *client, const struct imap_arg *args)
{
	struct mailbox_view *view = client->view;
	const char *str;

	if (args->type != IMAP_ARG_ATOM)
		return -1;
	str = t_str_ucase(IMAP_ARG_STR(args));
	args++;

	if (is_numeric(str, '\0')) {
		unsigned int num = strtoul(str, NULL, 10);

		if (args->type != IMAP_ARG_ATOM)
			return -1;
		str = t_str_ucase(IMAP_ARG_STR(args));
		args++;

		if (strcmp(str, "EXISTS") == 0)
			client_exists(client, num);

                if (num > array_count(&view->uidmap) &&
		    client->last_cmd->state > STATE_SELECT) {
			client_input_error(client, args-2,
				"seq too high (%u > %u, state=%s)",
				num, array_count(&view->uidmap),
                                states[client->last_cmd->state].name);
		} else if (strcmp(str, "EXPUNGE") == 0)
			mailbox_expunge(view, num);
		else if (strcmp(str, "RECENT") == 0) {
			view->recent_count = num;
			if (view->recent_count ==
			    array_count(&view->uidmap))
				view->storage->seen_all_recent = TRUE;
		} else if (!conf.no_tracking && strcmp(str, "FETCH") == 0)
			client_fetch(client, num, args);
	} else if (strcmp(str, "BYE") == 0) {
		if (client->last_cmd == NULL ||
		    client->last_cmd->state != STATE_LOGOUT) {
			str = args->type != IMAP_ARG_ATOM ? NULL :
				IMAP_ARG_STR(args);
			client_input_error(client, args, "Unexpected BYE");
		} else
			counters[client->last_cmd->state]++;
		client->login_state = LSTATE_NONAUTH;
	} else if (strcmp(str, "FLAGS") == 0)
		client_set_flags(client, args);
	else if (strcmp(str, "CAPABILITY") == 0)
		client_capability_parse(client, imap_args_to_str(args));
	else if (strcmp(str, "OK") == 0) {
		if (args->type != IMAP_ARG_ATOM)
			return -1;
		str = t_str_ucase(IMAP_ARG_STR(args));
		args++;
		if (*str != '[')
			return 0;
		str++;

		if (strcmp(str, "PERMANENTFLAGS") == 0) {
			if (args->type != IMAP_ARG_LIST)
				return -1;
			client_set_permanent_flags(client, args);
		} else if (view->select_uidnext == 0 &&
			   strcmp(str, "UIDNEXT") == 0) {
			if (args->type != IMAP_ARG_ATOM)
				return -1;
			str = IMAP_ARG_STR(args);
			view->select_uidnext =
				strtoul(t_strcut(str, ')'), NULL, 10);
		} else if (strcmp(str, "UIDVALIDITY") == 0) {
			unsigned int new_uidvalidity;

			if (args->type != IMAP_ARG_ATOM)
				return -1;
			str = IMAP_ARG_STR(args);
			new_uidvalidity = strtoul(t_strcut(str, ')'), NULL, 10);
			if (new_uidvalidity != view->storage->uidvalidity) {
				if (view->storage->uidvalidity != 0) {
					i_error("UIVALIDITY changed: %u -> %u",
						view->storage->uidvalidity,
						new_uidvalidity);
				}
				view->storage->uidvalidity = new_uidvalidity;
			}
		}
	} else if (strcmp(str, "NO") == 0) {
		/*i_info("%s: %s", client->username, line + 2);*/
	} else if (strcmp(str, "BAD") == 0) {
		client->refcount++;
		client_input_error(client, args, "BAD received");
	}
	return 0;
}

static const char *get_random_flags(struct mailbox_view *view)
{
	static const char *flags[] = {
		"\\Seen", "\\Flagged", "\\Draft", "\\Answered"
	};
	static const char *keywords[] = {
		"$Label1", "$Label2", "$Label3", "$Label4", "$Label5"
	};
	unsigned int i, idx;
	string_t *str;

	str = t_str_new(128);
	for (i = 0; i < N_ELEMENTS(flags); i++) {
		if ((rand() % 4) == 0) {
			if (str_len(str) != 0)
				str_append_c(str, ' ');
			str_append(str, flags[i]);
		}
	}

	if (!view->keywords_can_create_more &&
	    array_count(&view->keywords) == 0) {
		/* server doesn't support keywords */
		return str_c(str);
	}

	for (i = 0; i < N_ELEMENTS(keywords); i++) {
		if ((rand() % 4) == 0 &&
		    (view->keywords_can_create_more ||
		     mailbox_keyword_find(view, keywords[i], &idx))) {
			if (str_len(str) != 0)
				str_append_c(str, ' ');
			str_append(str, keywords[i]);
		}
	}

	// FIXME: remove this
	if (str_len(str) == 0)
		str_append(str, flags[0]);

#ifdef RAND_KEYWORDS
	if ((rand() % 10) == 0) {
		unsigned int j, len = (rand() % RAND_KEYWORDS) + 1;

		if (str_len(str) != 0)
			str_append_c(str, ' ');
		for (j = 0; j < len; j++)
			str_append_c(str, (rand() % 26) + 'A');
	}
#endif
	return str_c(str);
}

static void command_send(struct client *client, const char *cmdline,
			 command_callback_t *callback)
{
	struct command *cmd;
	const char *cmd_str;
	unsigned int tag = client->tag_counter++;

	i_assert(!client->append_unfinished);

	cmd = i_new(struct command, 1);
	cmd->cmdline = i_strdup(cmdline);
	cmd->state = client->state;
	cmd->tag = tag;
	cmd->callback = callback;

	cmd_str = t_strdup_printf("%u.%u %s\r\n", client->global_id,
				  tag, cmdline);
	o_stream_send_str(client->output, cmd_str);
	if (client->rawlog_output != NULL) {
		if (!client->rawlog_last_lf)
			o_stream_send_str(client->rawlog_output, "<<<\n");
		o_stream_send_str(client->rawlog_output, cmd_str);
		client->rawlog_last_lf = TRUE;
	}

	array_append(&client->commands, &cmd, 1);
	client->last_cmd = cmd;
}

static int client_append(struct client *client, bool continued)
{
	struct mbox_source *source = client->view->storage->source;
	string_t *cmd;
	struct istream *input;
	time_t t;
	off_t ret;

	if (!continued) {
		i_assert(client->append_size == 0);
		mbox_get_next_size(source, &client->append_size, &t);
		client->append_offset = source->input->v_offset;

		cmd = t_str_new(128);
		if (!client->append_unfinished)
			str_printfa(cmd, "APPEND \"%s\"", conf.mailbox);
		if ((rand() % 2) == 0) {
			str_printfa(cmd, " (%s)",
				    get_random_flags(client->view));
		}
		if ((rand() % 2) == 0)
			str_printfa(cmd, " \"%s\"", imap_to_datetime(t));
		str_printfa(cmd, " {%"PRIuUOFF_T, client->append_size);
		if ((client->capabilities & CAP_LITERALPLUS) != 0)
			str_append_c(cmd, '+');
		str_append_c(cmd, '}');

		if (client->append_unfinished) {
			/* continues the last APPEND call */
			str_append(cmd, "\r\n");
			o_stream_send_str(client->output, str_c(cmd));
		} else {
			client->state = STATE_APPEND;
			command_send(client, str_c(cmd), state_callback);
			client->append_unfinished = TRUE;
		}

		if ((client->capabilities & CAP_LITERALPLUS) == 0) {
			/* we'll have to wait for "+" */
			i_stream_skip(source->input, client->append_size);
			return 0;
		}
	} else {
		i_stream_seek(source->input, client->append_offset);
	}

	input = i_stream_create_limit(source->input,
				      source->input->v_offset,
				      client->append_size);
	ret = o_stream_send_istream(client->output, input);
        i_stream_unref(&input);

	if (ret < 0) {
		i_error("APPEND failed: %m");
		return -1;
	}
	client->append_size -= ret;
	client->append_offset += ret;

	if (client->append_size != 0) {
		/* unfinished */
		o_stream_set_flush_pending(client->output, TRUE);
		return 0;
	}

	if ((client->capabilities & CAP_MULTIAPPEND) != 0 &&
	    states[STATE_APPEND].probability_again != 0 &&
	    client->plan_size > 0 && client->plan[0] == STATE_APPEND) {
		/* we want to append another message.
		   do it in the same transaction. */
		return client_send_next_cmd(client);
	}

	client->append_unfinished = FALSE;
	o_stream_send_str(client->output, "\r\n");
	return 0;
}

static void command_unlink(struct client *client, struct command *cmd)
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

static void command_free(struct command *cmd)
{
	i_free(cmd->cmdline);
	i_free(cmd);
}

static void client_delay_timeout(void *context)
{
	struct client *client = context;

	i_assert(client->io == NULL);

	client->delayed = FALSE;
	client->last_io = ioloop_time;

	timeout_remove(&client->to);
	client->io = io_add(i_stream_get_fd(client->input),
			    IO_READ, client_input, client);
}

static void client_delay(struct client *client, unsigned int msecs)
{
	i_assert(client->to == NULL);

	client->delayed = TRUE;
	io_remove(&client->io);
	client->to = timeout_add(msecs, client_delay_timeout, client);
}

static bool do_rand(enum client_state state)
{
	return (rand() % 100) < states[state].probability;
}

static bool do_rand_again(enum client_state state)
{
	return (rand() % 100) < states[state].probability_again;
}

static void auth_plain_callback(struct client *client, struct command *cmd,
				const struct imap_arg *args,
				enum command_reply reply)
{
	buffer_t *str, *buf;

	if (reply == REPLY_OK) {
		state_callback(client, cmd, args, reply);
		return;
	}
	if (reply != REPLY_CONT) {
		client_input_error(client, args, "AUTHENTICATE failed");
		client_unref(client);
		return;
	}

	counters[cmd->state]++;

	buf = t_str_new(512);
	str_append_c(buf, '\0');
	str_append(buf, client->username);
	str_append_c(buf, '\0');
	str_append(buf, conf.password);

	str = t_str_new(512);
	base64_encode(buf->data, buf->used, str);
	str_append(str, "\r\n");

	o_stream_send_str(client->output, str_c(str));
}

static int client_handle_cmd_reply(struct client *client, struct command *cmd,
				   const struct imap_arg *args,
				   enum command_reply reply)
{
	const char *str, *line;
	unsigned int i;

	line = imap_args_to_str(args);
	switch (reply) {
	case REPLY_OK:
		if (cmd->state != STATE_DISCONNECT)
			counters[cmd->state]++;
		break;
	case REPLY_NO:
		switch (cmd->state) {
		case STATE_COPY:
		case STATE_MCREATE:
		case STATE_MDELETE:
			break;
		case STATE_FETCH:
		case STATE_FETCH2:
			/* possibly tried to fetch expunged messages.
			   don't hide all errors though. */
			if (strstr(line, "no longer exist") != NULL) {
				/* Zimbra */
				break;
			}
			if (strstr(line, "No matching messages") != NULL) {
				/* Cyrus */
				break;
			}
		default:
			client_input_error(client, args, "%s failed",
					   states[cmd->state].name);
			break;
		}
		break;

	case REPLY_BAD:
		client_input_error(client, args, "%s replied BAD",
				   states[cmd->state].name);
		return -1;
	case REPLY_CONT:
		if (cmd->state == STATE_APPEND)
			break;

		client_input_error(client, args,
				   "%s: Unexpected continuation",
				   states[cmd->state].name);
		return -1;
	}

	switch (cmd->state) {
	case STATE_AUTHENTICATE:
	case STATE_LOGIN:
		client->login_state = LSTATE_AUTH;
		if (reply != REPLY_OK) {
			/* authentication failed */
			return -1;
		}

		for (i = 0; i < 3 && !stalled; i++) {
			if (array_count(&clients) >= conf.clients_count)
				break;

			client_new(array_count(&clients),
				   client->view->storage->source);
		}
		break;
	case STATE_SELECT:
		client->login_state = LSTATE_SELECTED;
		break;
	case STATE_COPY:
		if (reply == REPLY_NO) {
			const char *arg = args->type == IMAP_ARG_ATOM ?
				IMAP_ARG_STR(args) : NULL;
			if (arg != NULL &&
			    strcasecmp(arg, "[TRYCREATE]") == 0) {
				str = t_strdup_printf("CREATE %s",
						      conf.copy_dest);
				client->state = STATE_COPY;
				command_send(client, str, state_callback);
				break;
			}
			client_input_error(client, args, "COPY failed");
		}
		break;
	case STATE_APPEND:
		if (reply == REPLY_CONT) {
			/* finish appending */
			if (client_append(client, TRUE) < 0)
				return -1;
			break;
		}
		break;
	case STATE_LOGOUT:
		if (client->login_state != LSTATE_NONAUTH) {
			/* untagged bye set state to DISCONNECT, so we
			   shouldn't get here. */
			i_error("Server didn't send BYE but: %s", line);
		}
		return -1;
	case STATE_DISCONNECT:
		return -1;
	default:
		break;
	}

	return 0;
}

static enum client_state client_eat_first_plan(struct client *client)
{
	enum client_state state;

	if (disconnect_clients)
		return STATE_LOGOUT;

	i_assert(client->plan_size > 0);
	state = client->plan[0];

	client->plan_size--;
	memmove(client->plan, client->plan + 1,
		sizeof(client->plan[0]) * client->plan_size);
	return state;
}

static int client_send_next_cmd(struct client *client)
{
	enum client_state state;
	string_t *cmd;
	const char *str;
	unsigned int i, j, seq1, seq2, count, msgs;

	state = client_eat_first_plan(client);

	msgs = array_count(&client->view->uidmap);
	if (msgs == 0 && states[state].login_state == LSTATE_SELECTED) {
		/* no messages, no point in doing this command */
		return 0;
	}

	client->state = state;
	switch (state) {
	case STATE_AUTHENTICATE:
		command_send(client, "AUTHENTICATE plain", auth_plain_callback);
		break;
	case STATE_LOGIN:
		str = t_strdup_printf("LOGIN \"%s\" \"%s\"",
				      client->username, conf.password);
		command_send(client, str, state_callback);
		break;
	case STATE_LIST:
		//str = t_strdup_printf("LIST \"\" * RETURN (X-STATUS (MESSAGES))");
		str = t_strdup_printf("LIST \"\" *");
		command_send(client, str, state_callback);
		break;
	case STATE_MCREATE:
		if (rand() % 2)
			str = t_strdup_printf("CREATE \"test/%d\"", rand() % 20);
		else
			str = t_strdup_printf("CREATE \"test/%d/%d\"", rand() % 20, rand() % 20);
		command_send(client, str, state_callback);
		break;
	case STATE_MDELETE:
		if (rand() % 2)
			str = t_strdup_printf("DELETE \"test/%d\"", rand() % 20);
		else
			str = t_strdup_printf("DELETE \"test/%d/%d\"", rand() % 20, rand() % 20);
		command_send(client, str, state_callback);
		break;
	case STATE_SELECT:
		if (client->login_state == LSTATE_SELECTED) {
			/* already selected, don't do it agai */
			break;
		}
		str = t_strdup_printf("SELECT \"%s\"", conf.mailbox);
		command_send(client, str, state_callback);
		break;
	case STATE_FETCH: {
		static const char *fields[] = {
			"UID", "FLAGS", "ENVELOPE", "INTERNALDATE",
			"BODY", "BODYSTRUCTURE"
		};
		static const char *header_fields[] = {
			"From", "To", "Cc", "Subject", "References",
			"In-Reply-To", "Message-ID", "Delivered-To"
		};
		if (msgs > 100) {
			seq1 = (rand() % msgs) + 1;
			seq2 = I_MIN(seq1 + 100, msgs);
		} else {
			seq1 = 1;
			seq2 = msgs;
		}
		cmd = t_str_new(512);
		str_printfa(cmd, "FETCH %u:%u (", seq1, seq2);
		for (i = (rand() % 4) + 1; i > 0; i--) {
			if ((rand() % 4) != 0) {
				str_append(cmd, fields[rand() %
						       N_ELEMENTS(fields)]);
			} else {
				str_append(cmd, "BODY.PEEK[HEADER.FIELDS (");
				for (j = (rand() % 4) + 1; j > 0; j--) {
					int idx = rand() %
						N_ELEMENTS(header_fields);
					str_append(cmd, header_fields[idx]);
					if (j != 1)
						str_append_c(cmd, ' ');
				}
				str_append(cmd, ")]");
			}
			if (i != 1)
				str_append_c(cmd, ' ');
		}
		str_append_c(cmd, ')');
		command_send(client, str_c(cmd), state_callback);
		break;
	}
	case STATE_FETCH2:
		str = t_strdup_printf("FETCH %lu (BODY.PEEK[])",
				      (random() % msgs) + 1);
		command_send(client, str, state_callback);
		break;
	case STATE_SEARCH:
		command_send(client, "SEARCH BODY hello", state_callback);
		break;
	case STATE_SORT:
		if ((rand() % 2) == 0)
			command_send(client, "SORT (SUBJECT) US-ASCII ALL", state_callback);
		else
			command_send(client, "SORT (SUBJECT) US-ASCII FLAGGED", state_callback);
		break;
	case STATE_THREAD:
		command_send(client, "THREAD REFERENCES US-ASCII ALL", state_callback);
		break;
	case STATE_COPY:
		i_assert(conf.copy_dest != NULL);

		seq1 = (rand() % msgs) + 1;
		seq2 = (rand() % (msgs - seq1 + 1));
		seq2 = seq1 + I_MIN(seq2, 5);
		str = t_strdup_printf("COPY %u:%u %s",
				      seq1, seq2, conf.copy_dest);
		command_send(client, str, state_callback);
		break;
	case STATE_STORE:
		cmd = t_str_new(512);
		count = rand() % (msgs < 10 ? msgs : I_MIN(msgs/5, 50));
		for (i = 0; i < count; i++)
			str_printfa(cmd, "%u,", (rand() % msgs) + 1);
		if (str_len(cmd) == 0)
			break;

		str_insert(cmd, 0, "STORE ");
		str_truncate(cmd, str_len(cmd) - 1);
		str_append_c(cmd, ' ');
		switch (rand() % 3) {
		case 0:
			str_append_c(cmd, '+');
			break;
		case 1:
			str_append_c(cmd, '-');
			break;
		default:
			break;
		}
		str_append(cmd, "FLAGS");
		if (conf.checkpoint_interval == 0)
			str_append(cmd, ".SILENT");
		str_printfa(cmd, " (%s)", get_random_flags(client->view));

		command_send(client, str_c(cmd), state_callback);
		break;
	case STATE_STORE_DEL:
		cmd = t_str_new(512);
		if (msgs > conf.message_count_threshold + 5) {
			count = rand() % (msgs - conf.message_count_threshold);
		} else {
			count = rand() % 5;
		}

		for (i = 0; i < count; i++)
			str_printfa(cmd, "%u,", (rand() % msgs) + 1);

		if (!client->view->storage->seen_all_recent &&
		    conf.checkpoint_interval != 0 && msgs > 0) {
			/* expunge everything so we can start checking RECENT
			   counts */
			str_truncate(cmd, 0);
			str_append(cmd, "1:*,");
		}
		if (str_len(cmd) == 0)
			break;

		str_insert(cmd, 0, "STORE ");
		str_truncate(cmd, str_len(cmd) - 1);
		str_append(cmd, " +FLAGS");
		if (conf.checkpoint_interval == 0)
			str_append(cmd, ".SILENT");
		str_append(cmd, " \\Deleted");

		command_send(client, str_c(cmd), state_callback);
		break;
	case STATE_EXPUNGE:
		command_send(client, "EXPUNGE", state_callback);
		break;
	case STATE_APPEND:
		if (msgs >= conf.message_count_threshold)
			break;

		if (client_append(client, FALSE) < 0)
			return -1;
		break;
	case STATE_STATUS:
		str = t_strdup_printf("STATUS \"%s\" (MESSAGES UNSEEN RECENT)",
				      conf.mailbox);
		command_send(client, str, state_callback);
		break;
	case STATE_NOOP:
		command_send(client, "NOOP", state_callback);
		break;
	case STATE_CHECK:
		command_send(client, "CHECK", state_callback);
		break;
	case STATE_LOGOUT:
		command_send(client, "LOGOUT", state_callback);
		break;

	case STATE_BANNER:
	case STATE_DISCONNECT:
	case STATE_DELAY:
	case STATE_CHECKPOINT:
	case STATE_COUNT:
		i_unreached();
	}
	return 0;
}

static enum client_state client_get_next_state(enum client_state state)
{
	i_assert(state < STATE_LOGOUT);

	for (;;) {
		if (!conf.random_states)
			state++;
		else {
			/* if we're not in selected state, we'll randomly do
			   LIST, SELECT, APPEND or LOGOUT */
			state = STATE_LIST +
				(rand() % (STATE_LOGOUT - STATE_LIST + 1));
		}

		if (do_rand(state))
			break;

		if (state == STATE_LOGOUT) {
			/* logout skipped, wrap */
			state = STATE_AUTHENTICATE + 1;
		}
	}
	return state;
}

static struct command *command_lookup(struct client *client, unsigned int tag)
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

static enum login_state flags2login_state(enum state_flags flags)
{
	if ((flags & FLAG_STATECHANGE_NONAUTH) != 0)
		return LSTATE_NONAUTH;
	else if ((flags & FLAG_STATECHANGE_AUTH) != 0)
		return LSTATE_AUTH;
	else if ((flags & FLAG_STATECHANGE_SELECTED) != 0)
		return LSTATE_SELECTED;

	i_unreached();
}

static enum state_flags
client_get_pending_cmd_flags(struct client *client,
			     enum login_state *new_lstate_r)
{
	enum state_flags state_flags = 0;
	struct command *const *cmds;
	unsigned int i, count;

	*new_lstate_r = client->login_state;
	cmds = array_get(&client->commands, &count);
	for (i = 0; i < count; i++) {
		enum state_flags flags = states[cmds[i]->state].flags;

		if ((flags & FLAG_STATECHANGE) != 0)
			*new_lstate_r = flags2login_state(flags);
		state_flags |= flags;
	}
	return state_flags;
}

static enum client_state client_update_plan(struct client *client)
{
	enum client_state state;
	enum login_state lstate;

	state = client->plan_size > 0 ?
		client->plan[client->plan_size - 1] : client->plan[0];
	if (client->plan_size > 0 &&
	    (states[state].flags & FLAG_STATECHANGE) != 0) {
		/* wait until the state change is done before making new
		   commands. */
		return client->plan[0];
	}
	if ((client_get_pending_cmd_flags(client, &lstate) &
	     FLAG_STATECHANGE) != 0)
		return state;

	if (state == STATE_LOGOUT)
		return state;

	while (client->plan_size <
	       sizeof(client->plan)/sizeof(client->plan[0])) {
		switch (client->login_state) {
		case LSTATE_NONAUTH:
			/* we begin with LOGIN/AUTHENTICATE commands */
			i_assert(client->plan_size == 0);
			state = do_rand(STATE_AUTHENTICATE) ?
				STATE_AUTHENTICATE : STATE_LOGIN;
			break;
		case LSTATE_AUTH:
		case LSTATE_SELECTED:
			if (!do_rand_again(state))
				state = client_get_next_state(state);
			break;
		}
		i_assert(state <= STATE_LOGOUT);

		if (states[state].login_state > client->login_state ||
		    (client->login_state != LSTATE_NONAUTH &&
		     (state == STATE_AUTHENTICATE || state == STATE_LOGIN))) {
			/* can't do this now */
			continue;
		}

		client->plan[client->plan_size++] = state;
		if ((states[state].flags & FLAG_STATECHANGE) != 0)
			break;
	}

	i_assert(client->plan_size > 0);
	state = client->plan[0];
	i_assert(states[state].login_state <= client->login_state);
	return state;
}

static bool client_pending_cmds_allow_statechange(struct client *client,
						  enum client_state state)
{
	enum login_state old_lstate, new_lstate = 0;
	struct command *const *cmds;
	unsigned int i, count;

	new_lstate = flags2login_state(states[state].flags);

	cmds = array_get(&client->commands, &count);
	for (i = 0; i < count; i++) {
		if ((states[cmds[i]->state].flags & FLAG_STATECHANGE) != 0)
			return FALSE;

		old_lstate = states[cmds[i]->state].login_state;
		if (new_lstate < old_lstate)
			return FALSE;
		if (new_lstate == old_lstate && new_lstate == LSTATE_SELECTED)
			return FALSE;
	}
	return TRUE;
}

static int client_send_more_commands(struct client *client)
{
	enum state_flags pending_flags;
	enum login_state new_lstate;
	enum client_state state;

	while (array_count(&client->commands) < MAX_COMMAND_QUEUE_LEN) {
		state = client_update_plan(client);
		i_assert(state <= STATE_LOGOUT);

		if (client->append_unfinished)
			break;
		if (conf.no_pipelining && array_count(&client->commands) > 0)
			break;

		if ((states[state].flags & FLAG_STATECHANGE) != 0) {
			/* this command would change the state. check if there
			   are any pending commands that don't like the
			   change */
			if (!client_pending_cmds_allow_statechange(client,
								   state))
				break;
		}
		pending_flags = client_get_pending_cmd_flags(client,
							     &new_lstate);
		if ((states[state].flags & FLAG_STATECHANGE) == 0 &&
		    (pending_flags & FLAG_STATECHANGE) != 0) {
			/* we're changing state. allow this command if its
			   required login_state is lower than the current
			   state or the state we're changing to. */
			if (new_lstate <= states[state].login_state ||
			    client->login_state < states[state].login_state)
				break;
		}
		if ((states[state].flags & FLAG_MSGSET) != 0 &&
		    (pending_flags & (FLAG_EXPUNGES | FLAG_STATECHANGE)) != 0) {
			/* msgset may become invalid if we send it now */
			break;
		}

		if (client_send_next_cmd(client) < 0)
			return -1;
	}

	if (!client->delayed && do_rand(STATE_DELAY)) {
		counters[STATE_DELAY]++;
		client_delay(client, DELAY);
	}
	return 0;
}

struct checkpoint_context {
	struct message_metadata_dynamic *messages;
	uint32_t *uids;
	unsigned int *flag_counts;
	unsigned int count;
	bool errors;
};

static void
checkpoint_update(struct checkpoint_context *ctx, struct client *client)
{
	struct mailbox_view *view = client->view;
	const struct message_metadata_dynamic *msgs;
	const uint32_t *uids;
	enum mail_flags this_flags, other_flags;
	unsigned int i, count, keywords_size;

	uids = array_get(&view->uidmap, &count);
	if (count != ctx->count) {
		ctx->errors = TRUE;
		i_error("Client %u: Mailbox has only %u of %u messages",
			client->global_id, count, ctx->count);
	}

	msgs = array_get(&view->messages, &count);
	keywords_size = (array_count(&view->keywords) + 7) / 8;
	for (i = 0; i < count; i++) {
		if (uids[i] == 0) {
			/* we don't have this message's metadata */
			continue;
		}
		if (ctx->uids[i] == 0)
			ctx->uids[i] = uids[i];
		if (uids[i] != ctx->uids[i]) {
			ctx->errors = TRUE;
			i_error("Client %u: Message seq=%u UID %u != %u",
				client->global_id, i + 1,
				uids[i], ctx->uids[i]);
			break;
		}

		if ((msgs[i].mail_flags & MAIL_FLAGS_SET) == 0)
			continue;
		ctx->flag_counts[i]++;
		if ((ctx->messages[i].mail_flags & MAIL_FLAGS_SET) == 0) {
			/* first one to set flags */
			ctx->messages[i].mail_flags = msgs[i].mail_flags;
			ctx->messages[i].keyword_bitmask =
				msgs[i].keyword_bitmask;
			continue;
		}

		if ((msgs[i].mail_flags & MAIL_RECENT) != 0 &&
		    !view->storage->dont_track_recent) {
			if ((ctx->messages[i].mail_flags & MAIL_RECENT) == 0)
				ctx->messages[i].mail_flags |= MAIL_RECENT;
			else {
				i_error("Client %u: Message seq=%u UID=%u "
					"has \\Recent flag in multiple sessions",
					client->global_id, i + 1, uids[i]);
				view->storage->dont_track_recent = TRUE;
			}
		}

		this_flags = msgs[i].mail_flags & ~MAIL_RECENT;
		other_flags = ctx->messages[i].mail_flags & ~MAIL_RECENT;
		if (this_flags != other_flags) {
			ctx->errors = TRUE;
			i_error("Client %u: Message seq=%u UID=%u "
				"flags differ: (%s) vs (%s)",
				client->global_id, i + 1, uids[i],
				flags2str(this_flags), flags2str(other_flags));
		}
		if (memcmp(msgs[i].keyword_bitmask,
			   ctx->messages[i].keyword_bitmask,
			   keywords_size) != 0) {
			ctx->errors = TRUE;
			i_error("Client %u: Message seq=%u UID=%u "
				"keywords differ: (%s) vs (%s)",
				client->global_id, i + 1, uids[i],
				keywords2str(view, msgs[i].keyword_bitmask),
				keywords2str(view, ctx->messages[i].keyword_bitmask));
		}
	}
}

static void checkpoint_check_missing_recent(struct checkpoint_context *ctx,
					    unsigned int min_uidnext)
{
	unsigned int i, client_count = array_count(&clients);

	/* find the first message that we know were created by ourself */
	for (i = 0; i < ctx->count; i++) {
		if (ctx->uids[i] > min_uidnext)
			break;
	}

	/* make sure \Recent flag is found from all of them */
	for (; i < ctx->count; i++) {
		if (ctx->flag_counts[i] != client_count ||
		    (ctx->messages[i].mail_flags & MAIL_FLAGS_SET) == 0)
			continue;
		if ((ctx->messages[i].mail_flags & MAIL_RECENT) == 0) {
			i_error("Message seq=%u UID=%u isn't \\Recent anywhere",
				i + 1, ctx->uids[i]);
		}
	}
}

static void checkpoint_neg(struct mailbox_storage *storage)
{
	struct checkpoint_context ctx;
	struct client *const *c;
	unsigned int min_uidnext = -1U, max_msgs_count = 0;
	unsigned int i, count, check_count = 0;
	unsigned int recent_total;
	bool orig_dont_track_recent = storage->dont_track_recent;

	i_assert(storage->checkpoint_clients_left > 0);
	if (--storage->checkpoint_clients_left > 0)
		return;

	c = array_get(&clients, &count);

	if (storage->checkpoint_state == CHECKPOINT_STATE_WAIT) {
		/* everyone's finally finished their commands. now send CHECK
		   to make sure everyone sees each others' changes */
		for (i = 0; i < count; i++) {
			if (c[i] == NULL || c[i]->checkpointing != storage)
				continue;

			/* send the checkpoint command */
			c[i]->plan[0] = STATE_CHECK;
			c[i]->plan_size = 1;
			(void)client_send_next_cmd(c[i]);
			storage->checkpoint_clients_left++;
		}
		storage->checkpoint_state = CHECKPOINT_STATE_CHECK;
		return;
	}
	i_assert(storage->checkpoint_state == CHECKPOINT_STATE_CHECK);
	storage->checkpoint_state = CHECKPOINT_STATE_NONE;

	/* get maximum number of messages in mailbox */
	recent_total = 0;
	for (i = 0; i < count; i++) {
		if (c[i] == NULL || c[i]->checkpointing != storage)
			continue;

		i_assert(array_count(&c[i]->commands) == 0);
		if (c[i]->view->select_uidnext != 0) {
			min_uidnext = I_MIN(min_uidnext,
					    c[i]->view->select_uidnext);
		}
		recent_total += c[i]->view->recent_count;
		max_msgs_count = I_MAX(max_msgs_count,
				       array_count(&c[i]->view->uidmap));
	}

	/* make sure everyone has the same idea of what the mailbox
	   looks like */
	memset(&ctx, 0, sizeof(ctx));
	if (max_msgs_count > 0) {
		ctx.count = max_msgs_count;
		ctx.messages = i_new(struct message_metadata_dynamic,
				     ctx.count);
		ctx.uids = i_new(uint32_t, ctx.count);
		ctx.flag_counts = i_new(uint32_t, ctx.count);
		for (i = 0; i < count; i++) {
			if (c[i] == NULL || c[i]->checkpointing != storage)
				continue;

			check_count++;
			checkpoint_update(&ctx, c[i]);
		}
		if (!storage->seen_all_recent || storage->dont_track_recent) {
			/* can't handle this */
		} else if (recent_total > ctx.count) {
			i_error("Total RECENT count %u larger than current "
				"message count %u", recent_total, ctx.count);
			storage->dont_track_recent = TRUE;
		} else if (total_disconnects == 0 &&
			   recent_total != ctx.count) {
			i_error("Total RECENT count %u != %u",
				recent_total, ctx.count);
			storage->dont_track_recent = TRUE;
		}
		if (total_disconnects == 0 && min_uidnext != 0 &&
		    !storage->dont_track_recent) {
			/* this only works if no clients have disconnected */
			checkpoint_check_missing_recent(&ctx, min_uidnext);
		}
		i_free(ctx.flag_counts);
		i_free(ctx.uids);
		i_free(ctx.messages);
	}
	if (!ctx.errors)
		counters[STATE_CHECKPOINT] += check_count;

	for (i = 0; i < count; i++) {
		if (c[i] == NULL)
			continue;
		if (c[i]->checkpointing == storage)
			c[i]->checkpointing = NULL;

		if (array_count(&c[i]->commands) == 0 &&
		    c[i]->state != STATE_BANNER) {
			(void)client_send_more_commands(c[i]);
			i_assert(array_count(&c[i]->commands) > 0);
		}
	}

	if (storage->dont_track_recent && !orig_dont_track_recent)
		i_warning("Disabling \\Recent flag tracking");
}

static void clients_checkpoint(struct mailbox_storage *storage)
{
	struct client *const *c;
	unsigned int i, count;

	if (storage->checkpoint_state != CHECKPOINT_STATE_NONE)
		return;
	storage->checkpoint_state = CHECKPOINT_STATE_WAIT;
	i_assert(storage->checkpoint_clients_left == 0);

	c = array_get(&clients, &count);
	for (i = 0; i < count; i++) {
		if (c[i] == NULL || c[i]->login_state != LSTATE_SELECTED)
			continue;

		if (c[i]->view->storage == storage) {
			c[i]->checkpointing = storage;
			if (array_count(&c[i]->commands) > 0)
				storage->checkpoint_clients_left++;
		}
	}
	if (storage->checkpoint_clients_left == 0) {
		storage->checkpoint_clients_left++;
		checkpoint_neg(storage);
	}
}

static void state_callback(struct client *client, struct command *cmd,
			   const struct imap_arg *args,
			   enum command_reply reply)
{
	if (client_handle_cmd_reply(client, cmd, args, reply) < 0) {
		client_unref(client);
		return;
	}

	if (client->checkpointing != NULL) {
		/* we're checkpointing */
		if (array_count(&client->commands) > 0)
			return;

		checkpoint_neg(client->view->storage);
		return;
	} else if (client->view->storage->checkpoint_clients_left > 0) {
		/* don't do anything until checkpointing is finished */
		return;
	}

	if (client_send_more_commands(client) < 0)
		client_unref(client);
}

static int
client_input_args(struct client *client, const struct imap_arg *args)
{
	const char *p, *tag, *tag_status;
	struct command *cmd;
	enum command_reply reply;

	if (args->type != IMAP_ARG_ATOM)
		return client_input_error(client, args, "Broken tag");
	tag = IMAP_ARG_STR(args);
	args++;

	if (strcmp(tag, "+") == 0) {
		if (client->last_cmd == NULL) {
			return client_input_error(client, args,
				"Unexpected command contination");
		}
		client->last_cmd->callback(client, client->last_cmd,
					   args, REPLY_CONT);
		return 0;
	}
	if (strcmp(tag, "*") == 0) {
		if (client_handle_untagged(client, args) < 0) {
			return client_input_error(client, args,
						  "Invalid untagged input");
		}
		return 0;
	}

	/* tagged reply */
	if (args->type != IMAP_ARG_ATOM) {
		return client_input_error(client, args,
					  "Broken tagged reply");
	}
	tag_status = IMAP_ARG_STR(args);
	args++;

	p = strchr(tag, '.');
	cmd = p != NULL &&
		atoi(t_strdup_until(tag, p)) == (int)client->global_id ?
		command_lookup(client, atoi(t_strcut(p+1, ' '))) : NULL;
	if (cmd == NULL) {
		return client_input_error(client, args,
					  "Unexpected tagged reply: %s", tag);
	}

	if (strcasecmp(tag_status, "OK") == 0)
		reply = REPLY_OK;
	else if (strcasecmp(tag_status, "NO") == 0)
		reply = REPLY_NO;
	else if (strcasecmp(tag_status, "BAD") == 0) {
		reply = REPLY_BAD;
		client->refcount++;
		client_input_error(client, args, "BAD reply for command: %s",
				   cmd->cmdline);
	} else {
		return client_input_error(client, args, "Broken tagged reply");
	}

	command_unlink(client, cmd);

	o_stream_cork(client->output);
	cmd->callback(client, cmd, args, reply);
	o_stream_uncork(client->output);
	command_free(cmd);
	return 0;
}

static bool client_skip_literal(struct client *client)
{
	const unsigned char *data;
	size_t size;

	if (client->literal_left == 0)
		return TRUE;

	data = i_stream_get_data(client->input, &size);
	if (size < client->literal_left) {
		client->literal_left -= size;
		i_stream_skip(client->input, size);
		return FALSE;
	} else {
		i_stream_skip(client->input, client->literal_left);
		client->literal_left = 0;
		return TRUE;
	}
}

static void client_input(struct client *client)
{
	const struct imap_arg *imap_args;
	const char *line, *p;
	uoff_t literal_size;
	const unsigned char *data;
	size_t size;
	bool fatal;
	int ret;

        client->last_io = ioloop_time;

	switch (i_stream_read(client->input)) {
	case 0:
		return;
	case -1:
		/* disconnected */
		client_unref(client);
		return;
	case -2:
		/* buffer full */
		i_error("line too long");
		client_unref(client);
		return;
	}

	if (client->rawlog_output != NULL) {
		data = i_stream_get_data(client->input, &size);
		i_assert(client->prev_size <= size);
		if (client->prev_size != size) {
			o_stream_send(client->rawlog_output,
				      data + client->prev_size,
				      size - client->prev_size);
			client->rawlog_last_lf = data[size-1] == '\n';
		}
	}

	if (!client->seen_banner) {
		/* we haven't received the banner yet */
		line = i_stream_next_line(client->input);
		if (line == NULL)
			return;
		client->seen_banner = TRUE;

		p = strstr(line, "[CAPABILITY ");
		if (p == NULL)
			command_send(client, "CAPABILITY", state_callback);
		else {
			client_capability_parse(client, t_strcut(p + 12, ']'));
			(void)client_update_plan(client);
			o_stream_cork(client->output);
			client_send_next_cmd(client);
			o_stream_uncork(client->output);
		}
	}

	while (client_skip_literal(client)) {
		ret = imap_parser_read_args(client->parser, 0,
					    IMAP_PARSE_FLAG_LITERAL_SIZE |
					    IMAP_PARSE_FLAG_ATOM_ALLCHARS,
					    &imap_args);
		if (ret == -2) {
			/* need more data */
			break;
		}
		if (ret < 0) {
			/* some error */
			client_input_error(client, NULL,
				"error parsing input: %s",
				imap_parser_get_error(client->parser, &fatal));
			return;
		}
		if (imap_args->type == IMAP_ARG_EOL) {
			/* FIXME: we get here, but we shouldn't.. */
			client->refcount++;
		} else {
			if (imap_parser_get_literal_size(client->parser,
							 &literal_size)) {
				if (literal_size <= MAX_INLINE_LITERAL_SIZE) {
					/* read the literal */
					imap_parser_read_last_literal(
						client->parser);
					continue;
				}
				/* literal too large. we still have to skip it
				   though. */
				client->literal_left = literal_size;
				continue;
			}

			/* FIXME: we should call this for large
			   literals too.. */
			client->refcount++;
			t_push();
			ret = client_input_args(client, imap_args);
			t_pop();
		}

		if (client->literal_left == 0) {
			/* skip CRLF */
			imap_parser_reset(client->parser);

			data = i_stream_get_data(client->input, &size);
			if (size > 0 && data[0] == '\r') {
				i_stream_skip(client->input, 1);
				data = i_stream_get_data(client->input, &size);
			}
			if (size > 0 && data[0] == '\n')
				i_stream_skip(client->input, 1);
		}

		if (!client_unref(client) || ret < 0)
			return;
	}

	if (do_rand(STATE_DISCONNECT)) {
		/* random disconnection */
		counters[STATE_DISCONNECT]++;
		client_unref(client);
		return;
	}

	(void)i_stream_get_data(client->input, &client->prev_size);
}

static void client_wait_connect(void *context)
{
	struct client *client = context;
	int err, fd;

	fd = i_stream_get_fd(client->input);
	err = net_geterror(fd);
	if (err != 0) {
		i_error("connect() failed: %s", strerror(err));
		client_unref(client);
		return;
	}

	io_remove(&client->io);
	client->io = io_add(fd, IO_READ, client_input, client);
}

static int client_output(void *context)
{
        struct client *client = context;
	int ret;

	o_stream_cork(client->output);
	ret = o_stream_flush(client->output);
	client->last_io = ioloop_time;

	if (client->append_size > 0) {
		if (client_append(client, TRUE) < 0)
			client_unref(client);
	}
	o_stream_uncork(client->output);

        return ret;
}

static struct mailbox_view *mailbox_view_new(struct mailbox_storage *storage)
{
	struct mailbox_view *view;

	view = i_new(struct mailbox_view, 1);
	view->storage = storage;
	i_array_init(&view->uidmap, 100);
	i_array_init(&view->messages, 100);
	i_array_init(&view->keywords, 128);
	return view;
}

static void mailbox_view_free(struct mailbox_view **_mailbox)
{
	struct mailbox_view *view = *_mailbox;
	struct mailbox_keyword *keywords;
	struct message_metadata_dynamic *metadata;
	unsigned int i, count;

	*_mailbox = NULL;

	keywords = array_get_modifiable(&view->keywords, &count);
	for (i = 0; i < count; i++)
		i_free(keywords[i].name);
	array_free(&view->keywords);

	metadata = array_get_modifiable(&view->messages, &count);
	for (i = 0; i < count; i++) {
		i_free(metadata[i].keyword_bitmask);
		if (metadata[i].ms != NULL) {
			message_metadata_static_unref(view->storage,
						      &metadata[i].ms);
		}
	}
	array_free(&view->messages);

	array_free(&view->uidmap);
	i_free(view);
}

static struct mailbox_storage *mailbox_storage_get(struct mbox_source *source)
{
	/* FIXME: for now we support only a single mailbox */
	if (global_storage == NULL) {
		global_storage = i_new(struct mailbox_storage, 1);
		global_storage->source = source;
		i_array_init(&global_storage->static_metadata, 128);
	}
	i_assert(global_storage->source == source);
	return global_storage;
}

static void mailbox_storage_free(struct mailbox_storage **_storage)
{
	struct mailbox_storage *storage = *_storage;

	*_storage = NULL;
	array_free(&storage->static_metadata);
	i_free(storage);
}

static struct client *client_new(unsigned int idx, struct mbox_source *source)
{
	struct client *client;
	int fd;

	i_assert(idx >= array_count(&clients) ||
		 *array_idx(&clients, idx) == NULL);
	/*if (stalled) {
		array_append(&stalled_clients, &idx, 1);
		return NULL;
	}*/

	fd = net_connect_ip(&conf.ip, conf.port, NULL);
	if (fd < 0) {
		i_error("connect() failed: %m");
		return NULL;
	}

	client = i_new(struct client, 1);
	client->refcount = 1;
	client->tag_counter = 1;
	client->idx = idx;
	client->global_id = ++global_id_counter;
	client->view = mailbox_view_new(mailbox_storage_get(source));
	client->fd = fd;
	client->input = i_stream_create_fd(fd, 1024*64, FALSE);
	client->output = o_stream_create_fd(fd, (size_t)-1, FALSE);
	if (conf.rawlog) {
		int log_fd;
		const char *rawlog_path;

		rawlog_path = t_strdup_printf("rawlog.%u", client->global_id);
		log_fd = open(rawlog_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
		if (log_fd == -1)
			i_fatal("creat(%s) failed: %m", rawlog_path);
		client->rawlog_output = o_stream_create_fd(log_fd, 0, TRUE);
		client->rawlog_last_lf = TRUE;
	}
	client->parser = imap_parser_create(client->input, NULL, (size_t)-1);
	client->io = io_add(fd, IO_READ, client_wait_connect, client);
	client->username = i_strdup_printf(conf.username_template,
					   (int)(random() % USER_RAND + 1),
					   (int)(random() % DOMAIN_RAND + 1));
        client->last_io = ioloop_time;
	i_array_init(&client->commands, 16);
	o_stream_set_flush_callback(client->output, client_output, client);
	clients_count++;

        array_idx_set(&clients, idx, &client);
        return client;
}

static bool client_unref(struct client *client)
{
	struct mailbox_storage *storage = client->view->storage;
	unsigned int idx = client->idx;
	struct command *const *cmds;
	unsigned int i, count;
	bool checkpoint;

	i_assert(client->refcount > 0);
	if (--client->refcount > 0)
		return TRUE;

	total_disconnects++;
	if (conf.disconnect_quit)
		exit(1);

	if (--clients_count == 0)
		stalled = FALSE;
	array_idx_clear(&clients, idx);

	cmds = array_get(&client->commands, &count);
	checkpoint = client->checkpointing != NULL;
	for (i = 0; i < count; i++)
		command_free(cmds[i]);
	array_free(&client->commands);

	if (clients_count == 0 && disconnect_clients)
		io_loop_stop(ioloop);
	if (client->io != NULL)
		io_remove(&client->io);
	if (client->to != NULL)
		timeout_remove(&client->to);
	if (close(client->fd) < 0)
		i_error("close(client) failed: %m");
	if (client->rawlog_output != NULL)
		o_stream_destroy(&client->rawlog_output);
	mailbox_view_free(&client->view);
	imap_parser_destroy(&client->parser);
	o_stream_unref(&client->output);
	i_stream_unref(&client->input);
	i_free(client->username);

	if (io_loop_is_running(ioloop) && !disconnect_clients) {
		client_new(idx, storage->source);
		if (!stalled) {
			const unsigned int *indexes;
			unsigned int i, count;

			indexes = array_get(&stalled_clients, &count);
			for (i = 0; i < count && i < 3; i++)
				client_new(indexes[i], storage->source);
			array_delete(&stalled_clients, 0, i);
		}
	}
	i_free(client);

	if (checkpoint)
		checkpoint_neg(storage);
	return FALSE;
}

#define STATE_IS_VISIBLE(state) \
	(states[i].probability != 0)

static void print_header(void)
{
	unsigned int i;
	bool have_agains = FALSE;

	for (i = 1; i < STATE_COUNT; i++) {
		if (!STATE_IS_VISIBLE(i))
			continue;
		printf("%s ", states[i].short_name);
	}
	printf("\n");
	for (i = 1; i < STATE_COUNT; i++) {
		if (!STATE_IS_VISIBLE(i))
			continue;
		if (states[i].probability_again)
			have_agains = TRUE;
		printf("%3d%% ", states[i].probability);
	}
	printf("\n");

	if (have_agains) {
		for (i = 1; i < STATE_COUNT; i++) {
			if (!STATE_IS_VISIBLE(i))
				continue;
			if (states[i].probability_again == 0)
				printf("     ");
			else
				printf("%3d%% ", states[i].probability_again);
		}
		printf("\n");
	}
}

static void print_timeout(void *context ATTR_UNUSED)
{
	struct client *const *c;
        static int rowcount = 0;
        unsigned int i, count, banner_waits, stall_count;

        if ((rowcount++ % 10) == 0)
                print_header();

        for (i = 1; i < STATE_COUNT; i++) {
		if (!STATE_IS_VISIBLE(i))
			continue;
		printf("%4d ", counters[i]);
		total_counters[i] += counters[i];
		counters[i] = 0;
        }

	stalled = FALSE;
	banner_waits = 0;
	stall_count = 0;

	c = array_get(&clients, &count);
	for (i = 0; i < count; i++) {
		if (c[i] != NULL && c[i]->state == STATE_BANNER) {
			banner_waits++;

			if (c[i]->last_io < ioloop_time - 15) {
				stall_count++;
				stalled = TRUE;
			}
                }
        }

	printf("%3d/%3d", (clients_count - banner_waits), clients_count);
	if (stall_count > 0)
		printf(" (%u stalled)", stall_count);

	if (array_count(&clients) < conf.clients_count) {
		printf(" [%d%%]", array_count(&clients) * 100 /
		       conf.clients_count);
	}

	printf("\n");
	for (i = 0; i < count; i++) {
		if (c[i] != NULL && c[i]->state != STATE_BANNER &&
		    c[i]->to == NULL && c[i]->last_io < ioloop_time - 15) {
			stalled = TRUE;
                        printf(" - %d. stalled for %u secs in %s\n", i,
                               (unsigned)(ioloop_time - c[i]->last_io),
                               states[c[i]->state].name);
                }
	}

	if (ioloop_time >= next_checkpoint_time &&
	    conf.checkpoint_interval > 0) {
		clients_checkpoint(global_storage);
		next_checkpoint_time = ioloop_time + conf.checkpoint_interval;
	}
}

static void print_total(void)
{
        unsigned int i;

	printf("\nTotals:\n");
	print_header();

        for (i = 1; i < STATE_COUNT; i++) {
		if (!STATE_IS_VISIBLE(i))
			continue;

		total_counters[i] += counters[i];
		printf("%4d ", total_counters[i]);
	}
	printf("\n");
}

static void fix_probabilities(void)
{
	unsigned int i;

	if (conf.copy_dest == NULL)
		states[STATE_COPY].probability = 0;
	if (conf.checkpoint_interval == 0)
		states[STATE_CHECKPOINT].probability = 0;
	else
		states[STATE_CHECKPOINT].probability = 100;

	if (states[STATE_LOGIN].probability != 100) {
		states[STATE_AUTHENTICATE].probability =
			100 - states[STATE_LOGIN].probability;
	} else if (states[STATE_AUTHENTICATE].probability != 0) {
		states[STATE_LOGIN].probability =
			100 - states[STATE_AUTHENTICATE].probability;
	}

	for (i = STATE_LIST; i <= STATE_LOGOUT; i++) {
		if (states[i].probability > 0)
			break;
	}
	if (i > STATE_LOGOUT)
		i_fatal("Invalid probabilities");
}

static void sig_die(int signo ATTR_UNUSED, void *context ATTR_UNUSED)
{
	if (!disconnect_clients) {
		/* try a nice way first by letting the clients
		   disconnect themselves */
		disconnect_clients = TRUE;
	} else {
		/* second time, die now */
		io_loop_stop(ioloop);
	}
	return_value = 1;
}

static void timeout_stop(void *context ATTR_UNUSED)
{
	disconnect_clients = TRUE;
}

static struct state *state_find(const char *name)
{
	unsigned int i;

	for (i = 0; i < STATE_COUNT; i++) {
		if (strcasecmp(states[i].name, name) == 0 ||
		    strcasecmp(states[i].short_name, name) == 0)
			return &states[i];
	}
	return NULL;
}

static void print_help(void)
{
	printf(
"imaptest [user=USER] [host=HOST] [port=PORT] [pass=PASSWORD] [mbox=MBOX] "
"         [clients=CC] [msgs=NMSG] [box=MAILBOX] [copybox=DESTBOX]\n"
"         [-] [<state>[=<n%%>[,<m%%>]]] [random] [no_pipelining] [no_tracking] "
"         [checkpoint=<secs>] "
"\n"
" USER = template for username. \"u%%04d\" will generate users \"u0001\" to\n"
"        \"u0099\". \"u%%04d@d%%04d\" will generate also \"d0001\" to \"d0099\".\n"
" MBOX = path to mbox from which we read mails to append.\n"
" MAILBOX = Mailbox name where to do all the work (default = INBOX).\n"
" DESTBOX = Mailbox name where to copy messages.\n"
" CC   = number of concurrent clients. [%u]\n"
" NMSG = target number of messages in the mailbox. [%u]\n"
"\n"
" -    = Sets all probabilities to 0%% except for LOGIN, LOGOUT and SELECT\n"
" <state> = Sets state's probability to n%% and repeated probability to m%%\n",
	CLIENTS_COUNT, MESSAGE_COUNT_THRESHOLD);
}

int main(int argc ATTR_UNUSED, char *argv[])
{
	struct timeout *to, *to_stop;
	struct client *const *c;
	struct ip_addr *ips;
	struct state *state;
	const char *key, *value;
	unsigned int i, count;
	int ret;

	lib_init();
	ioloop = io_loop_create();

	lib_signals_init();
        lib_signals_set_handler(SIGINT, TRUE, sig_die, NULL);

	conf.password = PASSWORD;
	conf.username_template = USERNAME_TEMPLATE;
	conf.host = HOST;
	conf.port = PORT;
	conf.mbox_path = home_expand(MBOX_PATH);
	conf.mailbox = "INBOX";
	conf.clients_count = CLIENTS_COUNT;
	conf.message_count_threshold = MESSAGE_COUNT_THRESHOLD;
	to_stop = NULL;

	for (argv++; *argv != NULL; argv++) {
		value = strchr(*argv, '=');
		key = value == NULL ? *argv :
			t_strdup_until(*argv, value);
		if (value != NULL) value++;

		if (strcmp(*argv, "-h") == 0 ||
		    strcmp(*argv, "--help") == 0) {
			print_help();
			return 0;
		}
		if (strcmp(key, "secs") == 0) {
			to_stop = timeout_add(atoi(value) * 1000,
					      timeout_stop, NULL);
			continue;
		}
		if (strcmp(key, "seed") == 0) {
			srand(atoi(value));
			continue;
		}

		if (strcmp(*argv, "-") == 0) {
			for (i = STATE_LOGIN+1; i < STATE_LOGOUT; i++) {
				if (i != STATE_SELECT)
					states[i].probability = 0;
			}
			continue;
		}

		state = state_find(key);
		if (state != NULL) {
			/* [<probability>[,<probability_again>]] */
			const char *p;

			if (value == NULL) {
				state->probability = 100;
				continue;
			}
			p = strchr(value, ',');
			if (p != NULL)
				value = t_strdup_until(value, p++);

			state->probability = atoi(value);
			if (p != NULL)
				state->probability_again = atoi(p);
			continue;
		}

		if (strcmp(*argv, "random") == 0) {
			conf.random_states = TRUE;
			continue;
		}
		if (strcmp(*argv, "no_pipelining") == 0) {
			conf.no_pipelining = TRUE;
			continue;
		}
		if (strcmp(*argv, "no_tracking") == 0) {
			conf.no_tracking = TRUE;
			continue;
		}
		if (strcmp(*argv, "disconnect_quit") == 0) {
			conf.disconnect_quit = TRUE;
			continue;
		}
		if (strcmp(*argv, "rawlog") == 0) {
			conf.rawlog = TRUE;
			continue;
		}

		/* pass=password */
		if (strcmp(key, "pass") == 0) {
			conf.password = value;
			continue;
		}

		/* mbox=path */
		if (strcmp(key, "mbox") == 0) {
			conf.mbox_path = home_expand(value);
			continue;
		}

		/* clients=# */
		if (strcmp(key, "clients") == 0) {
			conf.clients_count = atoi(value);
			continue;
		}

		/* msgs=# */
		if (strcmp(key, "msgs") == 0) {
			conf.message_count_threshold = atoi(value);
			continue;
		}
		/* checkpoint=# */
		if (strcmp(key, "checkpoint") == 0) {
			conf.checkpoint_interval = atoi(value);
			continue;
		}

		/* box=mailbox */
		if (strcmp(key, "box") == 0) {
			conf.mailbox = value;
			continue;
		}

		/* copybox=mailbox */
		if (strcmp(key, "copybox") == 0) {
			conf.copy_dest = value;
			continue;
		}
		if (strcmp(key, "user") == 0) {
			conf.username_template = value;
			continue;
		}
		if (strcmp(key, "host") == 0) {
			conf.host = value;
			continue;
		}
		if (strcmp(key, "port") == 0) {
			conf.port = atoi(value);
			continue;
		}

		printf("Unknown arg: %s\n", *argv);
		return 1;
	}
	if (conf.username_template == NULL)
		i_fatal("Missing username");

	if ((ret = net_gethostbyname(conf.host, &ips, &count)) != 0) {
		i_error("net_gethostbyname(%s) failed: %s",
			conf.host, net_gethosterror(ret));
		return 1;
	}
	conf.ip = ips[0];

	fix_probabilities();

	mbox_source = mbox_source_open(conf.mbox_path);
	next_checkpoint_time = ioloop_time + conf.checkpoint_interval;

	i_array_init(&clients, CLIENTS_COUNT);
	i_array_init(&stalled_clients, CLIENTS_COUNT);
	to = timeout_add(1000, print_timeout, NULL);
	for (i = 0; i < INIT_CLIENT_COUNT && i < conf.clients_count; i++)
		client_new(i, mbox_source);
        io_loop_run(ioloop);

	c = array_get(&clients, &count);
	for (i = 0; i < count; i++) {
		if (c[i] != NULL)
			client_unref(c[i]);
        }

	print_total();
	mbox_close(mbox_source);
	mailbox_storage_free(&global_storage);
	timeout_remove(&to);
	if (to_stop != NULL)
		timeout_remove(&to_stop);

	lib_signals_deinit();
	io_loop_destroy(&ioloop);
	lib_deinit();
	return return_value;
}
