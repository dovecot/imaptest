/* Copyright (c) 2007-2018 ImapTest authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "array.h"
#include "bsearch-insert-pos.h"
#include "str.h"
#include "hash.h"
#include "istream.h"
#include "message-date.h"
#include "message-header-decode.h"
#include "message-part-data.h"
#include "imap-envelope.h"
#include "imap-util.h"

#include "settings.h"
#include "client.h"
#include "mailbox-source.h"
#include "mailbox.h"

#include <stdlib.h>
#include <ctype.h>

#define MESSAGE_STATIC_REF0_KEEP_SECS 5

HASH_TABLE_TYPE(mailbox_storage) storages;

const char *mail_flag_names[] = {
	"\\Answered",
	"\\Flagged",
	"\\Deleted",
	"\\Seen",
	"\\Draft",
	"\\Recent"
};

static int metadata_static_cmp(const uint32_t *uidp,
			       struct message_metadata_static *const *ms)
{
	return *uidp < (*ms)->uid ? -1 :
		(*uidp > (*ms)->uid ? 1 : 0);
}

struct message_metadata_static *
message_metadata_static_lookup_seq(struct mailbox_view *view, uint32_t seq)
{
	const struct message_metadata_dynamic *metadata;
	unsigned int count;

	metadata = array_get(&view->messages, &count);
	return seq > count ? NULL : metadata[seq-1].ms;
}

void message_metadata_static_unref(struct mailbox_storage *storage,
				   struct message_metadata_static **_ms)
{
	struct message_metadata_static *ms = *_ms;
	unsigned int idx;

	*_ms = NULL;
	i_assert(ms->refcount > 0);
	if (--ms->refcount > 0)
		return;
	if (!ms->expunged) {
		/* unreferencing non-expunged messages get problematic if the
		   message owner client changes. so delay the final free. */
		ms->ref0_timeout = ioloop_time + MESSAGE_STATIC_REF0_KEEP_SECS;
		if (storage->static_metadata_ref0_count++ == 0) {
			storage->static_metadata_ref0_next_scan =
				ioloop_time + MESSAGE_STATIC_REF0_KEEP_SECS;
		}
		return;
	}

	if (!array_bsearch_insert_pos(&storage->static_metadata,
				      &ms->uid, metadata_static_cmp, &idx))
		i_unreached();
	else
		array_delete(&storage->static_metadata, idx, 1);

  if (ms->xguid != NULL) {
    //i_debug("..... xguid %s for uid: %ld", metadata->ms->xguid, uid);
    free(ms->xguid);
    ms->xguid = NULL;
  }
	i_free(ms);
}

static void message_metadata_static_free_old(struct mailbox_storage *storage)
{
	struct message_metadata_static **ms;
	unsigned int i, count, seen = 0;
	time_t oldest = 0;

	ms = array_get_modifiable(&storage->static_metadata, &count);
	i = 0;
	while (i < count && seen < storage->static_metadata_ref0_count) {
		if (ms[i]->refcount != 0) {
			i++;
			continue;
		}
		/* removed */
		if (ioloop_time < ms[i]->ref0_timeout) {
			if (oldest == 0 || oldest > ms[i]->ref0_timeout)
				oldest = ms[i]->ref0_timeout;
			i++; seen++;
			continue;
		}
		storage->static_metadata_ref0_count--;
		i_free(ms[i]);

		array_delete(&storage->static_metadata, i, 1);
		ms = array_get_modifiable(&storage->static_metadata, &count);
	}
	storage->static_metadata_ref0_next_scan = oldest;
}

struct message_metadata_static *
message_metadata_static_get(struct mailbox_storage *storage, uint32_t uid)
{
	struct message_metadata_static **base, *ms;
	const struct seq_range *range;
	unsigned int count, idx;
	uint32_t first_uid;

	if (storage->static_metadata_ref0_count > 0 &&
	    ioloop_time >= storage->static_metadata_ref0_next_scan)
		message_metadata_static_free_old(storage);

	base = array_get_modifiable(&storage->static_metadata, &count);
	if (bsearch_insert_pos(&uid, base, count, sizeof(*base),
			       metadata_static_cmp, &idx)) {
		ms = base[idx];
		if (ms->refcount++ == 0) {
			i_assert(storage->static_metadata_ref0_count > 0);
			storage->static_metadata_ref0_count--;
			ms->ref0_timeout = 0;
		}
		return ms;
	}

	/* see if we could compact expunged_uids array */
	first_uid = idx == 0 ? uid : base[0]->uid;
	range = array_get(&storage->expunged_uids, &count);
	if (count > 32 && first_uid > 2 && range[0].seq2 < first_uid-1) {
		seq_range_array_add_range(&storage->expunged_uids,
					  1, first_uid-1);
	}

	ms = i_new(struct message_metadata_static, 1);
	ms->uid = uid;
	ms->refcount = 1;
	array_insert(&storage->static_metadata, idx, &ms, 1);

	base = array_idx_modifiable(&storage->static_metadata, idx);
	return *base;
}

void message_metadata_static_assign_owner(struct mailbox_storage *storage,
					  struct message_metadata_static *ms)
{
	if (ms->owner_client_idx1 != 0 || !storage->assign_msg_owners)
		return;

	/* don't assign an owner if the message is already seen as expunged
	   in another session. it could already have had an owner and we could
	   still receive flag updates for it. */
	if (!seq_range_exists(&storage->expunged_uids, ms->uid))
		ms->owner_client_idx1 = clients_get_random_idx() + 1;
}

static void
mailbox_keywords_ref(struct mailbox_view *view, const uint8_t *bitmask)
{
	struct mailbox_keyword *keywords;
	unsigned int i, count;

	keywords = array_get_modifiable(&view->keywords, &count);
	for (i = 0; i < count; i++) {
		if ((bitmask[i/8] & (1 << (i%8))) != 0)
			keywords[i].msg_refcount++;
	}
}

static void
mailbox_keywords_drop(struct mailbox_view *view, const uint8_t *bitmask)
{
	struct mailbox_keyword *keywords;
	unsigned int i, count;

	keywords = array_get_modifiable(&view->keywords, &count);
	for (i = 0; i < count; i++) {
		if ((bitmask[i/8] & (1 << (i%8))) != 0) {
			i_assert(keywords[i].msg_refcount > 0);
			keywords[i].msg_refcount--;
		}
	}
}

void mailbox_view_expunge(struct mailbox_view *view, unsigned int seq)
{
	struct message_metadata_dynamic *metadata;
	const uint32_t *uidp;

	metadata = array_idx_modifiable(&view->messages, seq - 1);
	if (metadata->keyword_bitmask != NULL)
		mailbox_keywords_drop(view, metadata->keyword_bitmask);
	i_free(metadata->keyword_bitmask);

	if (metadata->ms != NULL) {
		seq_range_array_add(&view->storage->expunged_uids,
				    metadata->ms->uid);
		metadata->ms->expunged = TRUE;
		message_metadata_static_unref(view->storage, &metadata->ms);
	}
	uidp = array_idx(&view->uidmap, seq-1);
	if (*uidp != 0)
		view->known_uid_count--;
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

struct mailbox_keyword *
mailbox_view_keyword_get_by_name(struct mailbox_view *view,
				 const char *name)
{
	unsigned int idx;

	if (!mailbox_view_keyword_find(view, name, &idx)) {
		mailbox_view_keyword_add(view, name);
		if (!mailbox_view_keyword_find(view, name, &idx))
			i_unreached();
	}

	return mailbox_view_keyword_get(view, idx);
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
	if (storage->assign_flag_owners)
		kw->owner_client_idx1 = clients_get_random_idx() + 1;
	array_append(&storage->keyword_names, &kw, 1);
	return kw;
}

void mailbox_view_keyword_add(struct mailbox_view *view, const char *name)
{
	struct mailbox_keyword keyword;
	unsigned int count;

	i_zero(&keyword);
	keyword.name = mailbox_keyword_name_get(view->storage, name);
	keyword.flags_counter = view->flags_counter;
	array_append(&view->keywords, &keyword, 1);

	count = array_count(&view->keywords);
	if ((count+7)/8 > view->keyword_bitmask_alloc_size)
		mailbox_view_keywords_realloc(view, (count+7) / 8 * 4);
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
		metadata[i].keyword_bitmask =
			i_realloc(metadata[i].keyword_bitmask,
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

void mailbox_view_keywords_write(struct mailbox_view *view,
				 const uint8_t *bitmask, string_t *str)
{
	const struct mailbox_keyword *keywords;
	unsigned int i, count;

	if (bitmask == NULL)
		return;

	keywords = array_get(&view->keywords, &count);
	for (i = 0; i < count; i++) {
		if ((bitmask[i/8] & (1 << (i%8))) != 0) {
			if (str_len(str) > 0)
				str_append_c(str, ' ');
			str_append(str, keywords[i].name->name);
		}
	}
}

const char *mailbox_view_keywords_to_str(struct mailbox_view *view,
					 const uint8_t *bitmask)
{
	string_t *str;

	if (array_count(&view->keywords) == 0)
		return NULL;

	str = t_str_new(128);
	mailbox_view_keywords_write(view, bitmask, str);
	return str_c(str);
}

const char *mailbox_view_get_random_flags(struct mailbox_view *view,
					  unsigned int client_idx)
{
	struct mailbox_storage *storage = view->storage;
	static const char *keywords[] = {
		"$Label1", "$Label2", "$Label3", "$Label4", "$Label5"
	};
	struct mailbox_keyword *kw;
	unsigned int i, idx;
	string_t *str;

	if (!storage->flag_owner_clients_assigned &&
	    storage->assign_flag_owners) {
		i = 0;
		for (; i < N_ELEMENTS(storage->flags_owner_client_idx1); i++) {
			storage->flags_owner_client_idx1[i] =
				clients_get_random_idx() + 1;
		}
		storage->flag_owner_clients_assigned = TRUE;
	}

	str = t_str_new(128);
	for (i = 0; i < N_ELEMENTS(storage->flags_owner_client_idx1); i++) {
		if ((i_rand() % 2) != 0 || (1 << i) == MAIL_DELETED)
			continue;

		if (storage->assign_flag_owners &&
		    storage->flags_owner_client_idx1[i] != client_idx + 1) {
			/* not our flag, can't set it */
			continue;
		}

		if (str_len(str) != 0)
			str_append_c(str, ' ');
		str_append(str, mail_flag_names[i]);
	}

	if (!view->keywords_can_create_more &&
	    array_count(&view->keywords) == 0) {
		/* server doesn't support keywords */
		return str_c(str);
	}

	for (i = 0; i < N_ELEMENTS(keywords); i++) {
		if ((i_rand() % 4) != 0)
			continue;

		if (!mailbox_view_keyword_find(view, keywords[i], &idx))
			kw = NULL;
		else
			kw = mailbox_view_keyword_get(view, idx);
		if (kw == NULL && !view->keywords_can_create_more) {
			/* can't create it */
			continue;
		}

		if (storage->assign_flag_owners && kw != NULL &&
		    kw->name->owner_client_idx1 != client_idx + 1) {
			/* not our keyword, can't set it */
			continue;
		}
		if (str_len(str) != 0)
			str_append_c(str, ' ');
		str_append(str, keywords[i]);
	}

#ifdef RAND_KEYWORDS
	if ((i_rand() % 10) == 0) {
		unsigned int j, len = (i_rand() % RAND_KEYWORDS) + 1;

		if (str_len(str) != 0)
			str_append_c(str, ' ');
		for (j = 0; j < len; j++)
			str_append_c(str, (i_rand() % 26) + 'A');
	}
#endif
	return str_c(str);
}

static void
mailbox_metadata_free(struct mailbox_storage *storage,
		      ARRAY_TYPE(message_metadata_dynamic) *messages)
{
	struct message_metadata_dynamic *metadata;
	unsigned int i, count;

	metadata = array_get_modifiable(messages, &count);
	for (i = 0; i < count; i++) {
		i_free(metadata[i].keyword_bitmask);
		if (metadata[i].ms != NULL)
			message_metadata_static_unref(storage, &metadata[i].ms);
	}
}

static struct mailbox_offline_cache *
mailbox_offline_cache_alloc(struct mailbox_storage *storage)
{
	struct mailbox_offline_cache *cache;

	cache = i_new(struct mailbox_offline_cache, 1);
	cache->refcount = 1;
	cache->storage = storage;
	i_array_init(&cache->keywords, 64);
	i_array_init(&cache->uidmap, 128);
	i_array_init(&cache->messages, 128);
	return cache;
}

static void mailbox_offline_cache_free(struct mailbox_offline_cache *cache)
{
	mailbox_metadata_free(cache->storage, &cache->messages);
	array_free(&cache->keywords);
	array_free(&cache->uidmap);
	array_free(&cache->messages);
	i_free(cache);
}

struct mailbox_storage *
mailbox_storage_lookup(struct mailbox_source *source, const char *username,
		       const char *mailbox)
{
	struct mailbox_storage *storage;
	const char *guid;

	guid = t_strconcat(username, "\t", mailbox, NULL);
	storage = hash_table_lookup(storages, guid);
	if (storage == NULL)
		return NULL;

	i_assert(storage->source == source);
	return storage;
}

struct mailbox_storage *
mailbox_storage_get(struct mailbox_source *source, const char *username,
		    const char *mailbox)
{
	struct mailbox_storage *storage;
	const char *guid;

	guid = t_strconcat(username, "\t", mailbox, NULL);
	storage = hash_table_lookup(storages, guid);
	if (storage == NULL) {
		storage = i_new(struct mailbox_storage, 1);
		storage->guid = i_strdup(guid);
		storage->name = i_strdup(mailbox);
		storage->refcount = 1;
		storage->source = source;
		storage->assign_msg_owners = conf.own_msgs;
		storage->assign_flag_owners = conf.own_flags;
		i_array_init(&storage->expunged_uids, 128);
		i_array_init(&storage->static_metadata, 128);
		i_array_init(&storage->keyword_names, 64);
		hash_table_insert(storages, storage->guid, storage);
		mailbox_source_ref(storage->source);
	} else {
		i_assert(storage->source == source);
		storage->refcount++;
	}
	return storage;
}

void mailbox_storage_unref(struct mailbox_storage **_storage)
{
	struct mailbox_storage *storage = *_storage;

	*_storage = NULL;

	if (--storage->refcount > 0)
		return;

	hash_table_remove(storages, storage->guid);
	mailbox_storage_reset(storage);

	mailbox_source_unref(&storage->source);
	array_free(&storage->expunged_uids);
	array_free(&storage->static_metadata);
	array_free(&storage->keyword_names);
	i_free(storage->name);
	i_free(storage->guid);
	i_free(storage);
}

void mailbox_storage_reset(struct mailbox_storage *storage)
{
	struct mailbox_keyword_name **names;
	struct message_metadata_static **ms;
	unsigned int i, count;

	if (storage->cache != NULL) {
		i_assert(storage->cache->refcount == 1);
		mailbox_offline_cache_free(storage->cache);
		storage->cache = NULL;
	}

	names = array_get_modifiable(&storage->keyword_names, &count);
	for (i = 0; i < count; i++) {
		i_free(names[i]->name);
		i_free(names[i]);
	}
	array_clear(&storage->keyword_names);

	ms = array_get_modifiable(&storage->static_metadata, &count);
	for (i = 0; i < count; i++) {
		i_assert(ms[i]->refcount == 0);
		i_free(ms[i]);
	}
	array_clear(&storage->static_metadata);

	array_clear(&storage->expunged_uids);

	storage->uidvalidity = 0;
	storage->static_metadata_ref0_count = 0;
	storage->static_metadata_ref0_next_scan = 0;

	memset(storage->flags_owner_client_idx1, 0,
	       sizeof(storage->flags_owner_client_idx1));
	storage->assign_msg_owners = FALSE;
	storage->assign_flag_owners = FALSE;
	storage->flag_owner_clients_assigned = FALSE;
	storage->seen_all_recent = FALSE;
	storage->dont_track_recent = FALSE;
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

void mailbox_offline_cache_unref(struct mailbox_offline_cache **_cache)
{
	struct mailbox_offline_cache *cache = *_cache;

	i_assert(cache->refcount > 0);

	*_cache = NULL;
	if (--cache->refcount == 0)
		mailbox_offline_cache_free(cache);
}

bool mailbox_view_save_offline_cache(struct mailbox_view *view)
{
	struct mailbox_offline_cache *cache;
	const struct mailbox_keyword *keywords;
	const struct message_metadata_dynamic *metadata;
	struct message_metadata_dynamic new_metadata;
	unsigned int i, count, keyword_bytecount;

	if (view->known_uid_count != array_count(&view->uidmap)) {
		/* some UIDs are not known, can't really handle this */
		return FALSE;
	}

	if (view->highest_modseq == 0)
		return FALSE;

	if (view->storage->cache != NULL)
		mailbox_offline_cache_unref(&view->storage->cache);

	cache = view->storage->cache =
		mailbox_offline_cache_alloc(view->storage);
	cache->uidvalidity = view->storage->uidvalidity;
	cache->highest_modseq = view->highest_modseq;

	/* copy keywords */
	array_clear(&cache->keywords);
	keywords = array_get(&view->keywords, &count);
	keyword_bytecount = (count + 7) / 8;
	i_assert(keyword_bytecount <= view->keyword_bitmask_alloc_size);
	for (i = 0; i < count; i++)
		array_append(&cache->keywords, &keywords[i].name, 1);

	/* copy UID map */
	array_clear(&cache->uidmap);
	array_append_array(&cache->uidmap, &view->uidmap);

	/* copy messages */
	array_clear(&cache->messages);
	metadata = array_get(&view->messages, &count);
	for (i = 0; i < count; i++) {
		new_metadata = metadata[i];
		/* \Recent flags get dropped after a reconnection */
		new_metadata.mail_flags &= ~MAIL_RECENT;
		new_metadata.fetch_refcount = 0;
		new_metadata.flagchange_dirty_type = FLAGCHANGE_DIRTY_NO;

		if (metadata[i].keyword_bitmask != NULL) {
			new_metadata.keyword_bitmask =
				i_malloc(keyword_bytecount);
			memcpy(new_metadata.keyword_bitmask,
			       metadata[i].keyword_bitmask, keyword_bytecount);
		}
		if (new_metadata.ms != NULL)
			new_metadata.ms->refcount++;
		array_append(&cache->messages, &new_metadata, 1);
	}
	return TRUE;
}

void mailbox_view_restore_offline_cache(struct mailbox_view *view,
					struct mailbox_offline_cache *cache)
{
	ARRAY_TYPE(mailbox_keyword) old_keywords;
	struct mailbox_keyword_name *const *kw_names;
	const struct mailbox_keyword *keywords;
	struct mailbox_keyword *new_kw;
	const struct message_metadata_dynamic *metadata;
	struct message_metadata_dynamic new_metadata;
	unsigned int i, count;

	i_assert(array_count(&view->messages) == 0);

	view->highest_modseq = cache->highest_modseq;

	/* make a copy of old keywords - we need to set them back */
	t_array_init(&old_keywords, array_count(&view->keywords) + 1);
	array_append_array(&old_keywords, &view->keywords);

	/* copy keywords */
	array_clear(&view->keywords);
	kw_names = array_get(&cache->keywords, &count);
	for (i = 0; i < count; i++)
		mailbox_view_keyword_add(view, kw_names[i]->name);

	/* copy UID map */
	array_clear(&view->uidmap);
	array_append_array(&view->uidmap, &cache->uidmap);
	view->known_uid_count = array_count(&cache->uidmap);

	/* copy messages */
	array_clear(&view->messages);
	metadata = array_get(&cache->messages, &count);
	for (i = 0; i < count; i++) {
		new_metadata = metadata[i];
		if (metadata[i].keyword_bitmask != NULL) {
			new_metadata.keyword_bitmask =
				i_malloc(view->keyword_bitmask_alloc_size);
			memcpy(new_metadata.keyword_bitmask,
			       metadata[i].keyword_bitmask,
			       view->keyword_bitmask_alloc_size);
			mailbox_keywords_ref(view, new_metadata.keyword_bitmask);
		}
		if (new_metadata.ms != NULL)
			new_metadata.ms->refcount++;
		array_append(&view->messages, &new_metadata, 1);
	}

	/* add missing keywords and update permanent state of cached keywords */
	keywords = array_get(&old_keywords, &count);
	for (i = 0; i < count; i++) {
		new_kw = mailbox_view_keyword_get_by_name(view,
							keywords[i].name->name);
		new_kw->permanent = keywords[i].permanent;
	}
}

void mailbox_view_free(struct mailbox_view **_mailbox)
{
	struct mailbox_view *view = *_mailbox;

	*_mailbox = NULL;

	mailbox_metadata_free(view->storage, &view->messages);
	array_free(&view->messages);
	array_free(&view->keywords);

	array_free(&view->uidmap);
	i_free(view->last_thread_reply);
	i_free(view);
}

static bool
mailbox_global_parse_envelope(struct mailbox_source *source,
				     struct message_global *msg)
{
	struct message_part_envelope *env;
	const char *subject, *error;
	string_t *tmp;

	if (msg->envelope == NULL)
		return FALSE;

	msg->sent_date = (time_t)-1;
	msg->subject_utf8_tcase = NULL;
	if (!imap_envelope_parse(msg->envelope,
		pool_datastack_create(), &env, &error)) {
		i_error("Error parsing IMAP envelope: %s", error);
		return FALSE;
	}
	subject = env->subject;

	/* convert to UTF-8 */
	if (subject != NULL) {
		tmp = t_str_new(128);
		message_header_decode_utf8(
			(const unsigned char *)subject,
			strlen(subject), tmp,
			uni_utf8_to_decomposed_titlecase);
		subject = str_c(tmp);
	}
	msg->subject_utf8_tcase = p_strdup
		(mailbox_source_get_messages_pool(source), subject);

	if (env->date == NULL) {
		msg->sent_date = (time_t)-1;
	} else if (!message_date_parse
		((const unsigned char *)env->date, strlen(env->date),
			&msg->sent_date, &msg->sent_date_tz)) {
		msg->sent_date = (time_t)-1;
	}

	return TRUE;
}

bool mailbox_global_get_sent_date(struct mailbox_source *source,
				  struct message_global *msg,
				  time_t *date_r, int *tz_r)
{
	if (msg->sent_date == 0 &&
		!mailbox_global_parse_envelope(source, msg))
		return FALSE;

	*date_r = msg->sent_date;
	*tz_r = msg->sent_date_tz;
	return TRUE;
}

bool mailbox_global_get_subject_utf8(struct mailbox_source *source,
				     struct message_global *msg,
				     const char **subject_r)
{
	if (msg->subject_utf8_tcase == NULL &&
		!mailbox_global_parse_envelope(source, msg))
		return FALSE;

	*subject_r = msg->subject_utf8_tcase;
	return TRUE;
}

void mailboxes_init(void)
{
	hash_table_create(&storages, default_pool, 0, str_hash, strcmp);
}

void mailboxes_deinit(void)
{
	hash_table_destroy(&storages);
}
