/* Copyright (c) 2007-2016 Timo Sirainen */

#include "lib.h"
#include "hash.h"
#include "istream.h"
#include "istream-crlf.h"
#include "mbox-from.h"
#include "mailbox.h"
#include "mailbox-source-private.h"

#include <fcntl.h>
#include <unistd.h>

struct mbox_mailbox_source {
	struct mailbox_source source;

	int fd;
	char *path;
	struct istream *input;
	uoff_t next_offset;
};

static void mbox_mailbox_source_free(struct mailbox_source *_source)
{
	struct mbox_mailbox_source *source =
		(struct mbox_mailbox_source *)_source;

	if (source->input != NULL)
		i_stream_unref(&source->input);
	if (source->fd != -1)
		i_close_fd(&source->fd);
	i_free(source->path);
	i_free(source);
}

static void mbox_mailbox_source_open(struct mbox_mailbox_source *source)
{
	if (source->fd != -1)
		return;

	source->fd = open(source->path, O_RDONLY);
	if (source->fd == -1)
		i_fatal("open(%s) failed: %m", source->path);
	source->input = i_stream_create_fd(source->fd, (size_t)-1);
	i_stream_set_name(source->input, source->path);
}

static bool mbox_mailbox_source_eof(struct mailbox_source *_source)
{
	struct mbox_mailbox_source *source =
		(struct mbox_mailbox_source *)_source;

	mbox_mailbox_source_open(source);
	return i_stream_is_eof(source->input);
}

static struct istream *
mbox_mailbox_source_get_next(struct mailbox_source *_source,
			     uoff_t *vsize_r, time_t *time_r, int *tz_offset_r)
{
	struct mbox_mailbox_source *source =
		(struct mbox_mailbox_source *)_source;
	const char *line;
	char *sender;
	uoff_t offset, last_offset, vsize;
	time_t next_time;
	unsigned int linelen;
	int next_tz;

	mbox_mailbox_source_open(source);
	i_stream_seek(source->input, source->next_offset);

	line = i_stream_read_next_line(source->input);
	if (line == NULL) {
		if (source->input->v_offset == 0)
			i_fatal("Empty mbox file: %s", source->path);

		source->next_offset = 0;
		return mbox_mailbox_source_get_next(_source, vsize_r,
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

static const struct mailbox_source_vfuncs mbox_mailbox_source_vfuncs = {
	mbox_mailbox_source_free,
	mbox_mailbox_source_eof,
	mbox_mailbox_source_get_next,
};

struct mailbox_source *mailbox_source_new_mbox(const char *path)
{
	struct mbox_mailbox_source *source;

	source = i_new(struct mbox_mailbox_source, 1);
	source->path = i_strdup(path);
	source->fd = -1;
	source->source.v = mbox_mailbox_source_vfuncs;
	mailbox_source_init(&source->source);
	return &source->source;
}
