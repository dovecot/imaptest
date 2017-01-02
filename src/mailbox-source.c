/* Copyright (c) 2007-2017 ImapTest authors, see the included COPYING file */

#include "lib.h"
#include "hash.h"
#include "mailbox.h"
#include "mailbox-source-private.h"

struct mailbox_source *mailbox_source;

void mailbox_source_init(struct mailbox_source *source)
{
	source->refcount = 1;
	source->messages_pool = pool_alloconly_create("messages", 1024*1024);
	hash_table_create(&source->messages, default_pool, 0, str_hash, strcmp);
}

void mailbox_source_ref(struct mailbox_source *source)
{
	i_assert(source->refcount > 0);

	source->refcount++;
}

void mailbox_source_unref(struct mailbox_source **_source)
{
	struct mailbox_source *source = *_source;

	i_assert(source->refcount > 0);
	if (--source->refcount > 0)
		return;

	hash_table_destroy(&source->messages);
	pool_unref(&source->messages_pool);
	source->v.free(source);
}

bool mailbox_source_eof(struct mailbox_source *source)
{
	return source->v.eof(source);
}

struct istream *
mailbox_source_get_next(struct mailbox_source *source,
			uoff_t *vsize_r, time_t *time_r, int *tz_offset_r)
{
	return source->v.get_next(source, vsize_r, time_r, tz_offset_r);
}

pool_t mailbox_source_get_messages_pool(struct mailbox_source *source)
{
	return source->messages_pool;
}

struct message_global *
mailbox_source_get_msg(struct mailbox_source *source, const char *message_id)
{
	struct message_global *msg;

	msg = hash_table_lookup(source->messages, message_id);
	if (msg != NULL)
		return msg;

	/* new message */
	msg = p_new(source->messages_pool, struct message_global, 1);
	msg->message_id = p_strdup(source->messages_pool, message_id);
	hash_table_insert(source->messages, msg->message_id, msg);
	return msg;
}
