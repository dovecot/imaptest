/* Copyright (C) 2007 Timo Sirainen */

#include "lib.h"
#include "array.h"
#include "bsearch-insert-pos.h"
#include "str.h"
#include "istream.h"
#include "imap-util.h"

#include "settings.h"
#include "client.h"
#include "mailbox.h"

#include <stdlib.h>
#include <ctype.h>

struct mailbox_storage *global_storage = NULL;

static int metadata_static_cmp(const void *key, const void *data)
{
	const uint32_t *uidp = key;
	const struct message_metadata_static *const *ms = data;

	return *uidp < (*ms)->uid ? -1 :
		(*uidp > (*ms)->uid ? 1 : 0);
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

struct message_metadata_static *
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
	if (storage->assign_owners)
		ms->owner_client_idx1 = clients_get_random_idx() + 1;
	array_insert(&storage->static_metadata, idx, &ms, 1);

	base = array_get_modifiable(&storage->static_metadata, &count);
	return base[idx];
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

void mailbox_view_expunge(struct mailbox_view *view, unsigned int seq)
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

bool mailbox_view_keyword_find(struct mailbox_view *view, const char *name,
			       unsigned int *idx_r)
{
	const struct mailbox_keyword *keywords;
	unsigned int i, count;

	keywords = array_get(&view->keywords, &count);
	for (i = 0; i < count; i++) {
		if (strcasecmp(keywords[i].name->name, name) == 0) {
			*idx_r = i;
			return TRUE;
		}
	}
	return FALSE;
}

struct mailbox_keyword *mailbox_view_keyword_get(struct mailbox_view *view,
						 unsigned int idx)
{
	i_assert(idx < array_count(&view->keywords));
	return array_idx_modifiable(&view->keywords, idx);
}

static struct mailbox_keyword_name *
mailbox_keyword_name_get(struct mailbox_storage *storage, const char *name)
{
	struct mailbox_keyword_name *const *names, *kw;
	unsigned int i, count;

	names = array_get(&storage->keyword_names, &count);
	for (i = 0; i < count; i++) {
		if (strcasecmp(names[i]->name, name) == 0)
			return names[i];
	}

	kw = i_new(struct mailbox_keyword_name, 1);
	kw->name = i_strdup(name);
	array_append(&storage->keyword_names, &kw, 1);
	return kw;
}

void mailbox_view_keyword_add(struct mailbox_view *view, const char *name)
{
	struct mailbox_keyword keyword;

	memset(&keyword, 0, sizeof(keyword));
	keyword.name = mailbox_keyword_name_get(view->storage, name);
	keyword.flags_counter = view->flags_counter;
	array_append(&view->keywords, &keyword, 1);
}

void mailbox_keywords_clear(struct mailbox_view *view,
			    struct message_metadata_dynamic *metadata)
{
	if (view->keyword_bitmask_alloc_size == 0)
		return;

	if (metadata->keyword_bitmask == NULL) {
		metadata->keyword_bitmask =
			i_malloc(view->keyword_bitmask_alloc_size);
	} else {
		mailbox_keywords_drop(view, metadata->keyword_bitmask);
	}
	memset(metadata->keyword_bitmask, 0,
	       view->keyword_bitmask_alloc_size);
}

void mailbox_view_keywords_realloc(struct mailbox_view *view,
				   unsigned int new_alloc_size)
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

enum mail_flags mail_flag_parse(const char *str)
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

const char *mail_flags_to_str(enum mail_flags flags)
{
	string_t *str;

	str = t_str_new(40);
	imap_write_flags(str, flags, NULL);
	return str_c(str);
}

const char *mailbox_view_keywords_to_str(struct mailbox_view *view,
					 const uint8_t *bitmask)
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
			str_append(str, keywords[i].name->name);
		}
	}
	return str_c(str);
}

const char *mailbox_view_get_random_flags(struct mailbox_view *view)
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
		     mailbox_view_keyword_find(view, keywords[i], &idx))) {
			if (str_len(str) != 0)
				str_append_c(str, ' ');
			str_append(str, keywords[i]);
		}
	}

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

struct mailbox_storage *mailbox_storage_get(struct mailbox_source *source)
{
	/* FIXME: for now we support only a single mailbox */
	if (global_storage == NULL) {
		global_storage = i_new(struct mailbox_storage, 1);
		global_storage->source = source;
		global_storage->assign_owners = conf.own_msgs;
		i_array_init(&global_storage->static_metadata, 128);
		i_array_init(&global_storage->keyword_names, 64);
	}
	i_assert(global_storage->source == source);
	return global_storage;
}

void mailbox_storage_free(struct mailbox_storage **_storage)
{
	struct mailbox_storage *storage = *_storage;
	struct mailbox_keyword_name **names;
	unsigned int i, count;

	*_storage = NULL;

	names = array_get_modifiable(&storage->keyword_names, &count);
	for (i = 0; i < count; i++) {
		i_free(names[i]->name);
		i_free(names[i]);
	}

	array_free(&storage->static_metadata);
	array_free(&storage->keyword_names);
	i_free(storage);
}

struct mailbox_view *mailbox_view_new(struct mailbox_storage *storage)
{
	struct mailbox_view *view;

	view = i_new(struct mailbox_view, 1);
	view->storage = storage;
	i_array_init(&view->uidmap, 100);
	i_array_init(&view->messages, 100);
	i_array_init(&view->keywords, 128);
	return view;
}

void mailbox_view_free(struct mailbox_view **_mailbox)
{
	struct mailbox_view *view = *_mailbox;
	struct message_metadata_dynamic *metadata;
	unsigned int i, count;

	*_mailbox = NULL;

	metadata = array_get_modifiable(&view->messages, &count);
	for (i = 0; i < count; i++) {
		i_free(metadata[i].keyword_bitmask);
		if (metadata[i].ms != NULL) {
			message_metadata_static_unref(view->storage,
						      &metadata[i].ms);
		}
	}
	array_free(&view->messages);
	array_free(&view->keywords);

	array_free(&view->uidmap);
	i_free(view);
}
