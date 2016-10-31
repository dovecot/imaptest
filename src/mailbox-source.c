/* Copyright (c) 2007-2008 Timo Sirainen */

#include "lib.h"
#include "hash.h"
#include "istream.h"
#include "istream-crlf.h"
#include "mbox-from.h"
#include "mailbox.h"
#include "mailbox-source.h"

#include <fcntl.h>
#include <unistd.h>

struct mailbox_source {
	int refcount;

	int fd;
	char *path;
	struct istream *input;
	uoff_t next_offset;

	pool_t messages_pool;
	HASH_TABLE(char *, struct message_global *) messages;
};

struct mailbox_source *mailbox_source;

struct mailbox_source *mailbox_source_new(const char *path)
{
	struct mailbox_source *source;

	source = i_new(struct mailbox_source, 1);
	source->refcount = 1;
	source->path = i_strdup(path);
	source->fd = -1;

	source->messages_pool = pool_alloconly_create("messages", 1024*1024);
	hash_table_create(&source->messages, default_pool, 0, str_hash, strcmp);
	return source;
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
	if (source->input != NULL)
		i_stream_unref(&source->input);
	if (source->fd != -1)
		(void)close(source->fd);
	i_free(source->path);
	i_free(source);
}

static void mailbox_source_open(struct mailbox_source *source)
{
	if (source->fd != -1)
		return;

	source->fd = open(source->path, O_RDONLY);
	if (source->fd == -1)
		i_fatal("open(%s) failed: %m", source->path);
	source->input = i_stream_create_fd(source->fd, (size_t)-1);
	i_stream_set_name(source->input, source->path);
}

bool mailbox_source_eof(struct mailbox_source *source)
{
	mailbox_source_open(source);
	return i_stream_is_eof(source->input);
}

struct istream *
mailbox_source_get_next(struct mailbox_source *source,
			uoff_t *vsize_r, time_t *time_r, int *tz_offset_r)
{
	const char *line;
	char *sender;
	uoff_t offset, last_offset, vsize;
	time_t next_time;
	unsigned int linelen;
	int next_tz;

	mailbox_source_open(source);
	i_stream_seek(source->input, source->next_offset);

	line = i_stream_read_next_line(source->input);
	if (line == NULL) {
		if (source->input->v_offset == 0)
			i_fatal("Empty mbox file: %s", source->path);

		source->next_offset = 0;
		return mailbox_source_get_next(source, vsize_r,
					       time_r, tz_offset_r);
	}

	/* should be From-line */
	if (strncmp(line, "From ", 5) != 0 ||
	    mbox_from_parse((const unsigned char *)line+5, strlen(line+5),
			    time_r, tz_offset_r, &sender) < 0) {
		if (source->input->v_offset == 0)
			i_fatal("Not a valid mbox file: %s", source->path);
		i_panic("From-line not found at %"PRIuUOFF_T,
			source->input->v_offset);
	}
	i_free(sender);

	vsize = 0;
        offset = last_offset = source->input->v_offset;
        while ((line = i_stream_read_next_line(source->input)) != NULL) {
		linelen = strlen(line);
		if (strncmp(line, "From ", 5) == 0 &&
		    mbox_from_parse((const unsigned char *)line+5,
				    linelen-5, &next_time, &next_tz,
				    &sender) == 0) {
			i_free(sender);
			if (offset != last_offset)
                                break;

                        /* empty body */
                        offset = last_offset;
                }
		vsize += linelen + 2; /* count lines always as CR+LFs */
                last_offset = source->input->v_offset;
        }
        if (offset == last_offset)
                i_fatal("mbox file ends with From-line: %s", source->path);

	i_stream_seek(source->input, offset);

	source->next_offset = last_offset;
	*vsize_r = vsize;

	struct istream *input =
		i_stream_create_limit(source->input, last_offset - offset);
	struct istream *input2 = i_stream_create_crlf(input);
	i_stream_unref(&input);
	return input2;
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
