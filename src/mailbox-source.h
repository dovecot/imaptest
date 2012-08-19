#ifndef MAILBOX_SOURCE_H
#define MAILBOX_SOURCE_H

struct mailbox_source {
	int refcount;

	int fd;
	char *path;
	struct istream *input;
	uoff_t next_offset;

	pool_t messages_pool;
	HASH_TABLE(char *, struct message_global *) messages;
};

extern struct mailbox_source *mailbox_source;

struct mailbox_source *mailbox_source_new(const char *path);
void mailbox_source_unref(struct mailbox_source **source);

bool mailbox_source_eof(struct mailbox_source *source);
void mailbox_source_get_next_size(struct mailbox_source *source,
				  uoff_t *psize_r, uoff_t *vsize_r,
				  time_t *time_r, int *tz_offset_r);

#endif
