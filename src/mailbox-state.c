/* Copyright (c) 2007-2018 ImapTest authors, see the included COPYING file */

#include "lib.h"
#include "hash.h"
#include "istream.h"
#include "imap-date.h"
#include "imap-util.h"
#include "imap-arg.h"
#include "message-id.h"
#include "message-size.h"
#include "message-header-parser.h"

#include "settings.h"
#include "imap-client.h"
#include "mailbox.h"
#include "mailbox-source.h"
#include "mailbox-state.h"

#include <stdlib.h>

#define BODY_NIL_REPLY \
	"\"text\" \"plain\" NIL NIL NIL \"7bit\" 0 0"

#define ENVELOPE_NIL_REPLY \
	"NIL NIL NIL NIL NIL NIL NIL NIL NIL NIL"
#define INTERNALDATE_NIL_TIMESTAMP 0
#define RFC822_SIZE_NIL_REPLY "0"

static void client_fetch_envelope(struct imap_client *client,
				  struct message_metadata_dynamic *metadata,
				  const struct imap_arg *args,
				  unsigned int list_count, uint32_t uid)
{
	const char *str, *message_id, *orig_str;

	if (list_count < 9 || !imap_arg_get_nstring(&args[9], &str) ||
	    str == NULL)
		return;
	orig_str = str;

	message_id = message_id_get_next(&str);
	if (message_id == NULL || message_id_get_next(&str) != NULL) {
		imap_client_input_warn(client, "UID %u has invalid Message-Id: %s",
				       uid, orig_str);
		message_id = orig_str;
	}

	if (metadata->ms->msg != NULL) {
		if (strcmp(metadata->ms->msg->message_id, message_id) == 0)
			return;

		imap_client_input_warn(client,
			"UID %u changed Message-Id: %s -> %s",
			uid, metadata->ms->msg->message_id, message_id);
		return;
	}
	metadata->ms->msg =
		mailbox_source_get_msg(client->storage->source, message_id);
}

static const struct imap_arg *
fetch_list_get(const struct imap_arg *args, const char *name)
{
	const char *str;

	while (!IMAP_ARG_IS_EOL(args) && !IMAP_ARG_IS_EOL(&args[1])) {
		if (imap_arg_get_atom(args, &str) &&
		    strcasecmp(name, str) == 0)
			return &args[1];
		args += 2;
	}
	return NULL;
}

struct msg_old_flags {
	enum mail_flags flags;
	uint8_t *keyword_bitmask;
	unsigned int kw_alloc_size;
};

static bool
have_unexpected_changes(struct imap_client *client, const struct msg_old_flags *old,
			const struct message_metadata_dynamic *metadata)
{
	if (metadata->mail_flags != old->flags)
		return TRUE;

	if (old->kw_alloc_size != client->view->keyword_bitmask_alloc_size)
		return TRUE;
	return memcmp(old->keyword_bitmask, metadata->keyword_bitmask,
		      old->kw_alloc_size) != 0;
}

static void
check_unexpected_flag_changes(struct imap_client *client,
			      const struct msg_old_flags *old,
			      const struct message_metadata_dynamic *metadata)
{
	struct mailbox_storage *storage = client->storage;
	const struct mailbox_keyword *keywords;
	unsigned int i, new_count, new_alloc_size;
	const char *expunge_state;
	bool old_set, new_set;

	expunge_state = metadata->ms->expunged ? " (expunged)" : "";

	/* check flags */
	for (i = 0; i < N_ELEMENTS(storage->flags_owner_client_idx1); i++) {
		old_set = (old->flags & (1 << i)) != 0;
		new_set = (metadata->mail_flags & (1 << i)) != 0;
		if (old_set != new_set &&
		    storage->flags_owner_client_idx1[i] == client->client.idx + 1) {
			imap_client_state_error(client, "Owned flag changed: %s%s",
						mail_flag_names[i], expunge_state);
		}
	}

	/* check keywords */
	new_alloc_size = client->view->keyword_bitmask_alloc_size;
	keywords = array_get(&client->view->keywords, &new_count);
	for (i = 0; i < new_alloc_size; i++) {
		old_set = i >= old->kw_alloc_size ? FALSE :
			(old->keyword_bitmask[i/8] & (1 << (i%8))) != 0;
		new_set = (metadata->keyword_bitmask[i/8] & (1 << (i%8))) != 0;
		if (old_set != new_set &&
		    keywords[i].name->owner_client_idx1 == client->client.idx + 1) {
			imap_client_state_error(client,
				"Owned keyword changed: %s%s",
				keywords[i].name->name, expunge_state);
		}
	}
}

static void
message_metadata_set_flags(struct imap_client *client, const struct imap_arg *args,
			   struct message_metadata_dynamic *metadata)
{
	struct mailbox_view *view = client->view;
	struct mailbox_keyword *kw;
	struct msg_old_flags old_flags;
	enum mail_flags flag, flags = 0;
	unsigned int idx;
	const char *atom;

	old_flags.flags = metadata->mail_flags;
	old_flags.kw_alloc_size = view->keyword_bitmask_alloc_size;
	old_flags.keyword_bitmask = old_flags.kw_alloc_size == 0 ? NULL :
		t_malloc0(old_flags.kw_alloc_size);
	if (metadata->keyword_bitmask != NULL) {
		memcpy(old_flags.keyword_bitmask, metadata->keyword_bitmask,
		       old_flags.kw_alloc_size);
	}

	mailbox_keywords_clear(view, metadata);
	while (!IMAP_ARG_IS_EOL(args)) {
		if (!imap_arg_get_atom(args, &atom)) {
			imap_client_input_error(client,
				"Flags list contains non-atoms.");
			return;
		}

		if (*atom == '\\') {
			/* system flag */
			flag = mail_flag_parse(atom + 1);
			if (flag != 0)
				flags |= flag;
			else {
				imap_client_input_error(client,
					"Invalid system flag: %s", atom);
			}
		} else {
			if (!mailbox_view_keyword_find(view, atom, &idx)) {
				imap_client_state_error(client,
					"Keyword used without being in FLAGS: "
					"%s", atom);
				mailbox_view_keyword_add(view, atom);
				if (!mailbox_view_keyword_find(view, atom,
							       &idx))
					i_unreached();
			}
			i_assert(idx/8 < view->keyword_bitmask_alloc_size);
			kw = array_idx_modifiable(&view->keywords, idx);
			kw->msg_refcount++;
			i_assert(kw->msg_refcount <= array_count(&view->uidmap));
			metadata->keyword_bitmask[idx/8] |= 1 << (idx % 8);
		}

		args++;
	}
	metadata->mail_flags = flags | MAIL_FLAGS_SET;

	if ((old_flags.flags & MAIL_FLAGS_SET) == 0) {
		/* we don't know the old flags */
	} else if (metadata->flagchange_dirty_type != FLAGCHANGE_DIRTY_NO ||
		   client->qresync_select_cache != NULL) {
		/* we're changing the flags ourself */
	} else if (metadata->ms == NULL) {
		/* UID now known yet, don't do any owning checks */
	} else if (metadata->ms->owner_client_idx1 == client->client.idx+1) {
		if (have_unexpected_changes(client, &old_flags, metadata)) {
			imap_client_state_error(client,
				"Flags unexpectedly changed for owned message");
		}
	} else if (client->storage->assign_flag_owners)
		check_unexpected_flag_changes(client, &old_flags, metadata);

	if ((flags & MAIL_RECENT) != 0 && metadata->ms != NULL &&
	    !client->storage->dont_track_recent) {
		if (metadata->ms->recent_client_global_id == 0) {
			if (client->view->readwrite) {
				metadata->ms->recent_client_global_id =
					client->client.global_id;
			}
		} else if (metadata->ms->recent_client_global_id !=
			   client->client.global_id) {
			imap_client_state_error(client,
				"Message UID=%u has \\Recent flag in "
				"multiple sessions: %u and %u",
				metadata->ms->uid,
				client->client.global_id,
				metadata->ms->recent_client_global_id);
			client->storage->dont_track_recent = TRUE;
		}
	}

	if (metadata->fetch_refcount <= 1) {
		/* mark as seen, but don't mark undirty because we may see
		   more updates for this same message */
		if (metadata->flagchange_dirty_type != FLAGCHANGE_DIRTY_NO) {
			metadata->flagchange_dirty_type =
				FLAGCHANGE_DIRTY_MAYBE;
		}
	} else if (metadata->flagchange_dirty_type == FLAGCHANGE_DIRTY_YES)
		metadata->flagchange_dirty_type = FLAGCHANGE_DIRTY_WAITING;
}

static void
message_metadata_set_modseq(struct imap_client *client, const char *value,
			    struct message_metadata_dynamic *metadata)
{
	uint64_t modseq;
	uint32_t uid = metadata->ms == NULL ? 0 : metadata->ms->uid;

	if (str_to_uint64(value, &modseq) < 0 || modseq == 0) {
		imap_client_input_error(client, "UID=%u Invalid MODSEQ %s returned",
					uid, value);
		return;
	}
	if (modseq < metadata->modseq) {
		imap_client_input_warn(client,
				       "UID=%u MODSEQ dropped %s -> %s", uid,
				       dec2str(metadata->modseq), dec2str(modseq));
	}

	if (metadata->flagchange_dirty_type != FLAGCHANGE_DIRTY_NO ||
	    client->qresync_select_cache != NULL) {
		/* we're changing the flags ourself */
	} else if (metadata->ms == NULL) {
		/* UID now known yet, don't do any owning checks */
	} else if (metadata->ms->owner_client_idx1 == client->client.idx+1 &&
		   modseq != metadata->modseq) {
		imap_client_state_error(client,
			"UID=%u MODSEQ changed for owned message: %s -> %s",
			uid, dec2str(metadata->modseq), dec2str(modseq));
	}
	metadata->modseq = modseq;

	if (client->highest_untagged_modseq < modseq)
		client->highest_untagged_modseq = modseq;
}

static void
headers_parse(struct imap_client *client, struct istream *input,
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
			imap_client_state_error(client,
				"Unexpected header in reply: %s", hdr->name);
		} else if (headers[i].value_len == 0) {
			/* first header */
			new_value = hdr->full_value_len == 0 ? NULL :
				t_malloc_no0(hdr->full_value_len);
			memcpy(new_value, hdr->full_value, hdr->full_value_len);
			headers[i].value = new_value;
			headers[i].value_len = hdr->full_value_len;
			headers[i].missing = FALSE;
		} else {
			/* @UNSAFE: second header. append after first. */
			new_value = t_malloc_no0(headers[i].value_len + 1 +
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
headers_match(struct imap_client *client, ARRAY_TYPE(message_header) *headers_arr,
	      struct message_global *msg)
{
	pool_t pool = mailbox_source_get_messages_pool(client->storage->source);
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
			i_zero(&msg_header);
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
			imap_client_state_error(client,
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
fetch_parse_header_fields(struct imap_client *client, const struct imap_arg *args,
			  struct message_metadata_static *ms)
{
	const struct imap_arg *header_args, *arg;
	const char *header, *atom;
	struct message_header msg_header;
	struct istream *input;
	ARRAY_TYPE(message_header) headers;
	const struct message_header *fetch_headers = NULL;
	unsigned int i, fetch_count = 0;

	if (!imap_arg_get_list(args, &header_args))
		return -1;

	t_array_init(&headers, 8);
	for (arg = header_args; !IMAP_ARG_IS_EOL(arg); arg++) {
		i_zero(&msg_header);
		msg_header.missing = TRUE;
		if (!imap_arg_get_astring(arg, &msg_header.name))
			return -1;

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
	i_zero(&msg_header);
	msg_header.name = "";
	msg_header.missing = TRUE;
	array_append(&headers, &msg_header, 1);

	args++;
	if (!imap_arg_get_atom(args, &atom) || strcmp(atom, "]") != 0)
		return -1;
	args++;

	if (!imap_arg_get_nstring(args, &header))
		return -1;
	if (header == NULL) {
		/* expunged? */
		return 0;
	}
	if (*header == '\0' && args->type == IMAP_ARG_STRING) {
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

static void fetch_parse_body1(struct imap_client *client, const struct imap_arg *arg,
			      struct message_metadata_static *ms)
{
	pool_t pool = mailbox_source_get_messages_pool(client->storage->source);
	const char *body;
	unsigned int i, start, len;

	if (array_is_created(&ms->msg->body_words)) {
		if (array_count(&ms->msg->body_words) >= MSG_MAX_BODY_WORDS)
			return;
	} else {
		p_array_init(&ms->msg->body_words, pool, MSG_MAX_BODY_WORDS);
	}
	if (!imap_arg_get_nstring(arg, &body) || body == NULL)
		return;
	len = strlen(body);

	if (len > 0) {
		start = i_rand() % len;
		len = i_rand() % (len - start) + 1;
		if (len > 20)
			len = 20;
		/* make sure there are no non-ascii characters, since we don't
		   currently convert them to utf-8. also don't allow control
		   chars. */
		for (i = 0; i < len; i++) {
			if (body[start+i] < 32 ||
			    (unsigned char)body[start+i] >= 0x80) {
				len = i;
				break;
			}
		}
		if (len > 0) {
			body = p_strndup(pool, body + start, len);
			array_append(&ms->msg->body_words, &body, 1);
		}
	}
}

void mailbox_state_handle_fetch(struct imap_client *client, unsigned int seq,
				const struct imap_arg *args)
{
	struct mailbox_view *view = client->view;
	struct message_metadata_dynamic *metadata;
	const struct imap_arg *arg, *listargs;
  const char *name, *value, **p, *xguid;
  uoff_t value_size, *sizep;
	uint32_t uid, *uidp;
	unsigned int i, list_count;
	bool uid_changed = FALSE;

	uidp = array_idx_modifiable(&view->uidmap, seq-1);

	if (!imap_arg_get_list_full(args, &args, &list_count)) {
		imap_client_input_error(client, "FETCH didn't return a list");
		return;
	}

    arg = fetch_list_get(args, "x-guid");
    if (arg != NULL && imap_arg_get_atom(arg, &xguid)) {
    view->last_xguid = malloc(sizeof(char) * strlen(xguid) + 1);
    memcpy(view->last_xguid, xguid, strlen(xguid) + 1);
    }
	arg = fetch_list_get(args, "UID");
	if (arg == NULL && client->qresync_enabled) {
		imap_client_input_error(client,
			"FETCH didn't return UID while QRESYNC was enabled");
	}
	if (arg != NULL && imap_arg_get_atom(arg, &value)) {
		if (str_to_uint32(value, &uid) < 0 || uid == 0)
			imap_client_input_error(client, "Invalid UID number %s",
						value);
		else if (*uidp == 0) {
			view->known_uid_count++;
			*uidp = uid;
		} else if (*uidp != uid) {
			imap_client_input_error(client,
				"UID changed for sequence %u: %u -> %u",
				seq, *uidp, uid);
			uid_changed = TRUE;
			*uidp = uid;
		}
	}
	uid = *uidp;

	metadata = array_idx_get_space(&view->messages, seq - 1);
	if (metadata->ms == NULL && uid != 0) {
		metadata->ms =
			message_metadata_static_get(client->storage, uid);
	} else if (uid_changed && metadata->ms != NULL) {
		/* who knows what it contains now, just get rid of it */
		message_metadata_static_unref(client->storage, &metadata->ms);
		metadata->ms = NULL;
	}

	if (metadata->ms != NULL) {
    	i_assert(metadata->ms->uid == uid);
    	view->last_uid = uid;

    /* Get Message-ID from envelope if it exists. */
		arg = fetch_list_get(args, "ENVELOPE");
		if (arg != NULL) {
			const struct imap_arg *env_args;
			unsigned int env_list_count;

			if (!imap_arg_get_list_full(arg, &env_args,
						    &env_list_count)) {
				imap_client_input_error(client,
					"FETCH ENVELOPE didn't return a list");
				return;
			}

			client_fetch_envelope(client, metadata,
					      env_args, env_list_count, uid);
		}
	}

	/* the message is known, verify that everything looks ok */
	for (i = 0; i+1 < list_count; i += 2) {
		if (!imap_arg_get_atom(&args[i], &name))
			continue;

		name = t_str_ucase(name);
		listargs = NULL;
		if (imap_arg_get_nstring(&args[i+1], &value)) {
			if (value == NULL)
				continue;
		} else if (imap_arg_get_literal_size(&args[i+1], &value_size))
			value = dec2str(value_size);
		else if (imap_arg_get_list(&args[i+1], &listargs))
			value = imap_args_to_str(listargs);
		else
			continue;

		if (strcmp(name, "FLAGS") == 0) {
			if (listargs == NULL) {
				imap_client_input_error(client,
					"FLAGS reply isn't a list");
				continue;
			}
			message_metadata_set_flags(client, listargs, metadata);
			continue;
		}

		if (strcmp(name, "MODSEQ") == 0) {
			message_metadata_set_modseq(client, value, metadata);
			continue;
		}

		/* next follows metadata that require the UID to be known */
		if (metadata->ms == NULL)
			continue;

		if (strcmp(name, "INTERNALDATE") == 0) {
			time_t t;
			int tz_offset;

			if (!imap_parse_datetime(value, &t, &tz_offset)) {
				imap_client_input_error(client,
					"Broken INTERNALDATE");
			} else if (t == INTERNALDATE_NIL_TIMESTAMP) {
				/* ignore */
			} else if (metadata->ms->internaldate == 0) {
				metadata->ms->internaldate = t;
				metadata->ms->internaldate_tz = tz_offset;
			} else if (metadata->ms->internaldate != t ||
				   metadata->ms->internaldate_tz != tz_offset) {
				imap_client_input_error(client,
					"UID=%u INTERNALDATE changed "
					"%s+%d -> %s+%d", uid,
					dec2str(metadata->ms->internaldate),
					metadata->ms->internaldate_tz,
					dec2str(t), tz_offset);
			}
			continue;
		}

		/* next follows metadata that require the message to be known */
		if (metadata->ms->msg == NULL)
			continue;

		p = NULL; sizep = NULL; value_size = (uoff_t)-1;
		if (strcmp(name, "BODY") == 0) {
			if (strncasecmp(value, BODY_NIL_REPLY,
					strlen(BODY_NIL_REPLY)) == 0)
				continue;
			p = &metadata->ms->msg->body;
		} else if (strcmp(name, "BODYSTRUCTURE") == 0) {
			if (strncasecmp(value, BODY_NIL_REPLY,
					strlen(BODY_NIL_REPLY)) == 0)
				continue;
			p = &metadata->ms->msg->bodystructure;
		} else if (strcmp(name, "ENVELOPE") == 0) {
			if (strncasecmp(value, ENVELOPE_NIL_REPLY,
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
				if (fetch_parse_header_fields(client,
						args + i+1, metadata->ms) < 0) {
					imap_client_input_error(client,
						"Broken HEADER.FIELDS");
				}
			} else if (strcmp(name + 5, "]") == 0)
				sizep = &metadata->ms->msg->full_size;
			else if (strcmp(name + 5, "HEADER]") == 0)
				sizep = &metadata->ms->msg->header_size;
			else if (strcmp(name + 5, "TEXT]") == 0)
				sizep = &metadata->ms->msg->body_size;
			else if (strcmp(name + 5, "1]") == 0) {
				fetch_parse_body1(client, &args[i+1],
						  metadata->ms);
				sizep = &metadata->ms->msg->mime1_size;
			}
		}

		if (p != NULL && (*p == NULL || strcasecmp(*p, value) != 0)) {
			if (*p != NULL) {
				imap_client_state_error(client,
					"uid=%u %s: %s changed '%s' -> '%s'",
					metadata->ms->uid,
					metadata->ms->msg->message_id, name,
					*p, value);
			}
			*p = p_strdup(mailbox_source_get_messages_pool(view->storage->source),
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
				imap_client_state_error(client,
					"uid=%u %s: %s size changed %"PRIuUOFF_T
					" -> '%"PRIuUOFF_T"'",
					metadata->ms->uid,
					metadata->ms->msg->message_id, name,
					*sizep, value_size);
			}
			*sizep = value_size;
		}
	}
	if (i != list_count)
		imap_client_input_error(client, "FETCH reply doesn't have key-value pairs");

	/* assign owner only after processing FETCH so that we don't think the
	   FETCH changes caused a change yet */
	if (metadata->ms != NULL) {
		message_metadata_static_assign_owner(client->storage,
						     metadata->ms);
	}
}

int mailbox_state_set_flags(struct mailbox_view *view,
			    const struct imap_arg *args)
{
	const struct mailbox_keyword *keywords;
	struct mailbox_keyword *kw;
	unsigned int idx, i, count;
	const char *atom;
	bool errors = FALSE;

	if (!imap_arg_get_list(args, &args))
		return -1;

	view->flags_counter++;
	while (!IMAP_ARG_IS_EOL(args)) {
		if (!imap_arg_get_atom(args, &atom))
			return -1;

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
		    keywords[i].msg_refcount > 0) {
			i_error("Keyword '%s' dropped, but it still had "
				"%u references", keywords[i].name->name,
				keywords[i].msg_refcount);
			errors = TRUE;
		}
	}

	if (errors && conf.error_quit)
		exit(2);
	return 0;
}

int mailbox_state_set_permanent_flags(struct mailbox_view *view,
				      const struct imap_arg *args)
{
	struct mailbox_keyword *keywords, *kw;
	unsigned int idx, i, count;
	const char *atom;
	bool errors = FALSE;

	if (!imap_arg_get_list(args, &args))
		return -1;

	keywords = array_get_modifiable(&view->keywords, &count);
	for (i = 0; i < count; i++)
		keywords[i].permanent = FALSE;

	view->keywords_can_create_more = FALSE;
	while (!IMAP_ARG_IS_EOL(args)) {
		if (!imap_arg_get_atom(args, &atom))
			return -1;

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
		if (view->readwrite && !keywords[i].permanent &&
		    !keywords[i].name->seen_nonpermanent &&
		    keywords[i].flags_counter == view->flags_counter) {
			i_warning("Keyword not in PERMANENTFLAGS found: %s",
				  keywords[i].name->name);
			keywords[i].name->seen_nonpermanent = TRUE;
		} else if (keywords[i].permanent &&
			   keywords[i].flags_counter != view->flags_counter) {
			i_error("PERMANENTFLAGS keyword not in FLAGS: %s",
				keywords[i].name->name);
			errors = TRUE;
		}
	}
	if (errors && conf.error_quit)
		exit(2);
	return 0;
}
