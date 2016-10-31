#ifndef MAILBOX_SOURCE_PRIVATE_H
#define MAILBOX_SOURCE_PRIVATE_H

#include "mailbox-source.h"

struct mailbox_source_vfuncs {
	void (*free)(struct mailbox_source *source);
	bool (*eof)(struct mailbox_source *source);
	struct istream *(*get_next)(struct mailbox_source *source,
				    uoff_t *vsize_r,
				    time_t *time_r, int *tz_offset_r);
};

struct mailbox_source {
	int refcount;
	struct mailbox_source_vfuncs v;

	pool_t messages_pool;
	HASH_TABLE(char *, struct message_global *) messages;
};

void mailbox_source_init(struct mailbox_source *source);

#endif
