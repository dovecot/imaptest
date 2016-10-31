#ifndef MAILBOX_SOURCE_H
#define MAILBOX_SOURCE_H

extern struct mailbox_source *mailbox_source;

struct mailbox_source *mailbox_source_new(const char *path);
void mailbox_source_ref(struct mailbox_source *source);
void mailbox_source_unref(struct mailbox_source **source);

bool mailbox_source_eof(struct mailbox_source *source);
struct istream *
mailbox_source_get_next(struct mailbox_source *source,
			uoff_t *vsize_r, time_t *time_r, int *tz_offset_r);

pool_t mailbox_source_get_messages_pool(struct mailbox_source *source);
struct message_global *
mailbox_source_get_msg(struct mailbox_source *source, const char *message_id);

#endif
