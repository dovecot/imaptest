/* Copyright (C) 2007 Timo Sirainen */

#include "lib.h"
#include "hash.h"
#include "istream.h"
#include "imap-date.h"
#include "imap-parser.h"
#include "message-size.h"
#include "message-header-parser.h"

#include "settings.h"
#include "imap-args.h"
#include "client.h"
#include "mailbox.h"
#include "mailbox-source.h"
#include "mailbox-state.h"

#include <stdlib.h>

#define BODY_NIL_REPLY \
	"\"text\" \"plain\" NIL NIL NIL \"7bit\" 0 0 NIL NIL NIL"
#define ENVELOPE_NIL_REPLY \
	"NIL NIL NIL NIL NIL NIL NIL NIL NIL NIL"
#define INTERNALDATE_NIL_TIMESTAMP 0
#define RFC822_SIZE_NIL_REPLY "0"

static void client_fetch_envelope(struct client *client,
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

		client_input_error(client,
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

static void
message_metadata_set_flags(struct client *client, const struct imap_arg *args,
			   struct message_metadata_dynamic *metadata)
{
	struct mailbox_view *view = client->view;
	struct mailbox_keyword *kw;
	uint8_t *old_keywords;
	enum mail_flags flag, flags = 0;
	unsigned int idx, old_size;
	const char *atom;

	old_size = view->keyword_bitmask_alloc_size;
	old_keywords = old_size == 0 ? NULL : t_malloc0(old_size);
	if (metadata->keyword_bitmask != NULL) {
		memcpy(old_keywords, metadata->keyword_bitmask,
		       old_size);
	}

	mailbox_keywords_clear(view, metadata);
	while (args->type != IMAP_ARG_EOL) {
		if (args->type != IMAP_ARG_ATOM) {
			client_input_error(client,
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
				client_input_error(client,
					"Invalid system flag: %s", atom);
			}
		} else if (!mailbox_view_keyword_find(view, atom, &idx)) {
			client_input_error(client, 
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
	flags |= MAIL_FLAGS_SET;

	if ((metadata->mail_flags & MAIL_FLAGS_SET) == 0 ||
	    metadata->flagchange_dirty != 0) {
		/* we don't know the old flags */
	} else if (metadata->ms->owner_client_idx1 == client->idx+1) {
		if ((metadata->mail_flags != flags ||
		     old_size != view->keyword_bitmask_alloc_size ||
		     memcmp(old_keywords, metadata->keyword_bitmask,
			    old_size) != 0)) {
			client_input_error(client,
				"Flags unexpectedly changed for owned message");
		}
	}

	metadata->mail_flags = flags;
	if (metadata->fetch_refcount <= 1)
		metadata->flagchange_dirty = -1;
}

static void
headers_parse(struct client *client, struct istream *input,
	      ARRAY_TYPE(message_header) *headers_arr)
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
			client_input_error(client, 
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

static void
headers_match(struct client *client, ARRAY_TYPE(message_header) *headers_arr,
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
			client_input_error(client, 
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
	headers_parse(client, input, &headers);
	i_stream_destroy(&input);

	headers_match(client, &headers, ms->msg);
	return 0;
}

void mailbox_state_handle_fetch(struct client *client, unsigned int seq,
				const struct imap_arg *args)
{
	struct mailbox_view *view = client->view;
	struct message_metadata_dynamic *metadata;
	const ARRAY_TYPE(imap_arg_list) *list;
	const struct imap_arg *arg;
	const char *name, *value, **p;
	uoff_t value_size, *sizep;
	uint32_t uid, *uidp;
	unsigned int i, list_count;

	uidp = array_idx_modifiable(&view->uidmap, seq-1);

	if (args->type != IMAP_ARG_LIST) {
		client_input_error(client, "FETCH didn't return a list");
		return;
	}

	arg = fetch_list_get(args, "UID");
	if (arg != NULL && arg->type == IMAP_ARG_ATOM) {
		value = IMAP_ARG_STR(arg);
		uid = strtoul(value, NULL, 10);
		if (*uidp == 0)
			*uidp = uid;
		else if (*uidp != uid) {
			client_input_error(client,
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
		else if (args[i+1].type == IMAP_ARG_LITERAL_SIZE)
			value = dec2str(IMAP_ARG_LITERAL_SIZE(&args[i+1]));
		else if (args[i+1].type == IMAP_ARG_LIST) {
			list = IMAP_ARG_LIST(&args[i+1]);
			value = imap_args_to_str(array_idx(list, 0));
		} else
			continue;

		if (strcmp(name, "FLAGS") == 0) {
			if (list == NULL) {
				client_input_error(client,
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
				client_input_error(client,
						   "Broken INTERNALDATE");
			} else if (t == INTERNALDATE_NIL_TIMESTAMP) {
				/* ignore */
			} else if (metadata->ms->internaldate == 0)
				metadata->ms->internaldate = t;
			else if (metadata->ms->internaldate != t) {
				client_input_error(client,
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

		p = NULL; sizep = NULL; value_size = (uoff_t)-1;
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
		} else if (strncmp(name, "RFC822", 6) == 0) {
			if (name[6] == '\0')
				sizep = &metadata->ms->msg->full_size;
			else if (strcmp(name + 6, ".SIZE") == 0) {
				if (strcmp(value, RFC822_SIZE_NIL_REPLY) == 0)
					continue;
				sizep = &metadata->ms->msg->full_size;
				value_size = strtoull(value, NULL, 10);
			} else if (strcmp(name + 6, "HEADER") == 0)
				sizep = &metadata->ms->msg->header_size;
			else if (strcmp(name + 6, "TEXT") == 0)
				sizep = &metadata->ms->msg->body_size;
		} else if (strncmp(name, "BODY[", 5) == 0) {
			if (strcmp(name + 5, "HEADER.FIELDS") == 0) {
				if (fetch_parse_header_fields(client, args, i+1,
							metadata->ms) < 0) {
					client_input_error(client,
						"Broken HEADER.FIELDS");
				}
			} else if (strcmp(name + 5, "]") == 0)
				sizep = &metadata->ms->msg->full_size;
			else if (strcmp(name + 5, "HEADER]") == 0)
				sizep = &metadata->ms->msg->header_size;
			else if (strcmp(name + 5, "TEXT]") == 0)
				sizep = &metadata->ms->msg->body_size;
			else if (strcmp(name + 5, "1]") == 0)
				sizep = &metadata->ms->msg->mime1_size;
		}

		if (p != NULL && (*p == NULL || strcasecmp(*p, value) != 0)) {
			if (*p != NULL) {
				client_input_error(client,
					"uid=%u %s: %s changed '%s' -> '%s'",
					metadata->ms->uid,
					metadata->ms->msg->message_id, name,
					*p, value);
			}
			*p = p_strdup(view->storage->source->messages_pool,
				      value);
		} else if (sizep != NULL) {
			if (value_size == (uoff_t)-1) {
				/* not RFC822.SIZE - get the size */
				if (args[i+1].type == IMAP_ARG_LITERAL_SIZE)
					value_size = strtoull(value, NULL, 10);
				else
					value_size = strlen(value);
			}
			if (*sizep != value_size && *sizep != 0) {
				client_input_error(client,
					"uid=%u %s: %s size changed %"PRIuUOFF_T
					" -> '%"PRIuUOFF_T"'",
					metadata->ms->uid,
					metadata->ms->msg->message_id, name,
					*sizep, value_size);
			}
			*sizep = value_size;
		}
	}
	t_pop();
}

int mailbox_state_set_flags(struct mailbox_view *view,
			    const struct imap_arg *args)
{
	const ARRAY_TYPE(imap_arg_list) *list;
	const struct mailbox_keyword *keywords;
	struct mailbox_keyword *kw;
	unsigned int idx, i, count;
	const char *atom;
	bool errors = FALSE;

	if (args->type != IMAP_ARG_LIST)
		return -1;
	list = IMAP_ARG_LIST(args);
	args = array_idx(list, 0);

	view->flags_counter++;
	while (args->type != IMAP_ARG_EOL) {
		if (args->type != IMAP_ARG_ATOM)
			return -1;

		atom = IMAP_ARG_STR(args);
		if (*atom == '\\') {
			/* system flag */
			if (mail_flag_parse(atom + 1) == 0)
				return -1;
		} else if (!mailbox_view_keyword_find(view, atom, &idx))
			mailbox_view_keyword_add(view, atom);
		else {
			kw = mailbox_view_keyword_get(view, idx);
			kw->flags_counter = view->flags_counter;
		}

		args++;
	}

	keywords = array_get(&view->keywords, &count);
	for (i = 0; i < count; i++) {
		if (keywords[i].flags_counter != view->flags_counter &&
		    keywords[i].refcount > 0) {
			i_error("Keyword '%s' dropped, but it still had "
				"%d references", keywords[i].name->name,
				keywords[i].refcount);
			errors = TRUE;
		}
	}

	if (errors && conf.error_quit)
		exit(2);
	if ((count+7)/8 > view->keyword_bitmask_alloc_size)
		mailbox_view_keywords_realloc(view, (count+7) / 8 * 4);
	return 0;
}

int mailbox_state_set_permanent_flags(struct mailbox_view *view,
				      const struct imap_arg *args)
{
	const ARRAY_TYPE(imap_arg_list) *list;
	struct mailbox_keyword *keywords, *kw;
	unsigned int idx, i, count;
	const char *atom;
	bool errors = FALSE;

	if (args->type != IMAP_ARG_LIST)
		return -1;
	list = IMAP_ARG_LIST(args);
	args = array_idx(list, 0);

	keywords = array_get_modifiable(&view->keywords, &count);
	for (i = 0; i < count; i++)
		keywords[i].permanent = FALSE;

	view->keywords_can_create_more = FALSE;
	while (args->type != IMAP_ARG_EOL) {
		if (args->type != IMAP_ARG_ATOM)
			return -1;

		atom = IMAP_ARG_STR(args);
		if (*atom == '\\') {
			if (strcmp(atom, "\\*") == 0)
				view->keywords_can_create_more = TRUE;
			else if (mail_flag_parse(atom + 1) == 0)
				return -1;
		} else if (!mailbox_view_keyword_find(view, atom, &idx)) {
			i_error("Keyword in PERMANENTFLAGS not introduced "
				"with FLAGS: %s", atom);
			errors = TRUE;
		} else {
			kw = mailbox_view_keyword_get(view, idx);
			kw->permanent = TRUE;
		}
		args++;
	}

	keywords = array_get_modifiable(&view->keywords, &count);
	for (i = 0; i < count; i++) {
		if (!keywords[i].permanent && !keywords[i].seen_nonpermanent) {
			i_warning("Keyword not in PERMANENTFLAGS found: %s",
				  keywords[i].name->name);
			keywords[i].seen_nonpermanent = TRUE;
		}
	}
	if (errors && conf.error_quit)
		exit(2);
	return 0;
}
