/* Copyright (c) 2016 Timo Sirainen */

#include "lib.h"
#include "hash.h"
#include "istream.h"
#include "istream-crlf.h"
#include "mbox-from.h"
#include "mailbox.h"
#include "mailbox-source-private.h"

#include <fcntl.h>
#include <unistd.h>
#include <time.h>

struct random_mailbox_source {
	struct mailbox_source source;
	size_t max_size;
};

static void random_mailbox_source_free(struct mailbox_source *_source)
{
	i_free(_source);
}

static bool
random_mailbox_source_eof(struct mailbox_source *_source ATTR_UNUSED)
{
	return TRUE; /* shouldn't really matter */
}

static struct istream *
random_mailbox_source_get_next(struct mailbox_source *_source,
			       uoff_t *vsize_r, time_t *time_r, int *tz_offset_r)
{
	struct random_mailbox_source *source =
		(struct random_mailbox_source *)_source;
	size_t buf_size = (rand() % source->max_size) + 1;
	unsigned char *buf = i_malloc(buf_size);
	for (size_t i = 0; i < buf_size; i++) {
		buf[i] = rand();
		if (buf[i] == '\r' || buf[i] == '\n') {
			if (i+1 == buf_size)
				buf[i] = ' ';
			else {
				buf[i] = '\r';
				buf[++i] = '\n';
			}
		}
	}

	struct istream *input =
		i_stream_create_copy_from_data(buf, buf_size);
	i_free(buf);
	*time_r = time(NULL);
	*tz_offset_r = 0;
	*vsize_r = buf_size;
	return input;
}

static const struct mailbox_source_vfuncs random_mailbox_source_vfuncs = {
	random_mailbox_source_free,
	random_mailbox_source_eof,
	random_mailbox_source_get_next,
};

struct mailbox_source *mailbox_source_new_random(size_t max_size)
{
	struct random_mailbox_source *source;

	source = i_new(struct random_mailbox_source, 1);
	source->max_size = max_size;
	source->source.v = random_mailbox_source_vfuncs;
	mailbox_source_init(&source->source);
	return &source->source;
}
