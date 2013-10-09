/* Copyright (c) 2007-2008 Timo Sirainen */

#include "lib.h"
#include "istream.h"
#include "lmtp-client.h"
#include "settings.h"
#include "mailbox-source.h"
#include "imaptest-lmtp.h"

#include <sys/time.h>

struct imaptest_lmtp_delivery {
	struct timeval tv_start;
	struct lmtp_client *client;
	char *rcpt_to;
	struct istream *data_input;
};

static void imaptest_lmtp_free(struct imaptest_lmtp_delivery *d)
{
	lmtp_client_deinit(&d->client);
	if (d->data_input != NULL)
		i_stream_unref(&d->data_input);
	i_free(d->rcpt_to);
	i_free(d);
}

static void imaptest_lmtp_finish(void *context)
{
	struct imaptest_lmtp_delivery *d = context;

	imaptest_lmtp_free(d);
}

static void
imaptest_lmtp_rcpt_to_callback(bool success, const char *reply, void *context)
{
	struct imaptest_lmtp_delivery *d = context;

	if (!success)
		i_error("LMTP: RCPT TO <%s> failed: %s", d->rcpt_to, reply);
}

static void
imaptest_lmtp_data_callback(bool success, const char *reply, void *context)
{
	struct imaptest_lmtp_delivery *d = context;

	if (!success)
		i_error("LMTP: DATA for <%s> failed: %s", d->rcpt_to, reply);
}

void imaptest_lmtp_send(unsigned int port, const char *rcpt_to,
			struct mailbox_source *source)
{
	struct lmtp_client_settings lmtp_set;
	struct imaptest_lmtp_delivery *d;
	uoff_t mail_size, vsize;
	time_t t;
	int tz;

	memset(&lmtp_set, 0, sizeof(lmtp_set));
	lmtp_set.my_hostname = "localhost";
	lmtp_set.mail_from = "<>";

	d = i_new(struct imaptest_lmtp_delivery, 1);
	d->rcpt_to = i_strdup(rcpt_to);
	gettimeofday(&d->tv_start, NULL);
	d->client = lmtp_client_init(&lmtp_set, imaptest_lmtp_finish, d);
	if (lmtp_client_connect_tcp(d->client, LMTP_CLIENT_PROTOCOL_LMTP,
				    net_ip2addr(&conf.ips[0]), port) < 0)
		imaptest_lmtp_free(d);
	lmtp_client_add_rcpt(d->client, rcpt_to, imaptest_lmtp_rcpt_to_callback,
			     imaptest_lmtp_data_callback, d);

	mailbox_source_get_next_size(source, &mail_size, &vsize, &t, &tz);
	d->data_input = i_stream_create_limit(source->input, mail_size);
	lmtp_client_send(d->client, d->data_input);
}
