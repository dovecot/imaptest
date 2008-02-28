/* Copyright (C) 2007 Timo Sirainen */

#include "lib.h"
#include "hash.h"
#include "istream.h"
#include "src/lib-storage/index/mbox/mbox-from.h"
#include "mailbox-source.h"

#include <fcntl.h>
#include <unistd.h>

struct mailbox_source *mailbox_source;

struct mailbox_source *mailbox_source_new(const char *path)
{
	struct mailbox_source *source;

	source = i_new(struct mailbox_source, 1);
	source->refcount = 1;
	source->path = i_strdup(path);
	source->fd = open(path, O_RDONLY);
	if (source->fd == -1)
		i_fatal("open(%s) failed: %m", path);
	source->input = i_stream_create_fd(source->fd, (size_t)-1, FALSE);

	source->messages_pool = pool_alloconly_create("messages", 1024*1024);
	source->messages = hash_create(default_pool, default_pool, 0, str_hash,
				       (hash_cmp_callback_t *)strcmp);
	return source;
}

void mailbox_source_unref(struct mailbox_source **_source)
{
	struct mailbox_source *source = *_source;

	i_assert(source->refcount > 0);
	if (--source->refcount > 0)
		return;

	hash_destroy(&source->messages);
	pool_unref(&source->messages_pool);
	i_stream_unref(&source->input);
	(void)close(source->fd);
	i_free(source->path);
	i_free(source);
}

bool mailbox_source_eof(struct mailbox_source *source)
{
	if (!source->input->eof)
		(void)i_stream_read(source->input);
	return i_stream_have_bytes_left(source->input) == 0;
}

void mailbox_source_get_next_size(struct mailbox_source *source,
				  uoff_t *psize_r, uoff_t *vsize_r,
				  time_t *time_r)
{
	const char *line;
	char *sender;
	uoff_t offset, last_offset, vsize;
	time_t next_time;
	unsigned int linelen;

	i_stream_seek(source->input, source->next_offset);

	line = i_stream_read_next_line(source->input);
	if (line == NULL) {
		if (source->input->v_offset == 0)
			i_fatal("Empty mbox file: %s", source->path);

		source->next_offset = 0;
		mailbox_source_get_next_size(source, psize_r, vsize_r, time_r);
		return;
	}

	/* should be From-line */
	if (strncmp(line, "From ", 5) != 0 ||
	    mbox_from_parse((const unsigned char *)line+5, strlen(line+5),
			    time_r, &sender) < 0) {
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
				    linelen-5, &next_time, &sender) == 0) {
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
	*psize_r = last_offset - offset;
	*vsize_r = vsize;
}
