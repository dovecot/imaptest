#ifndef MAILBOX_SOURCE_H
#define MAILBOX_SOURCE_H

struct mailbox_source {
	int fd;
	char *path;
	struct istream *input;
	uoff_t next_offset;

	pool_t messages_pool;
	struct hash_table *messages;
};

extern struct mailbox_source *mailbox_source;

struct mailbox_source *mailbox_source_new(const char *path);
void mailbox_source_free(struct mailbox_source **source);

void mailbox_source_get_next_size(struct mailbox_source *source, uoff_t *size_r,
				  time_t *time_r);

#endif
