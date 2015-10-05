/* Copyright (c) 2007-2008 Timo Sirainen */

#include "lib.h"
#include "llist.h"
#include "ioloop.h"
#include "istream.h"
#include "lmtp-client.h"
#include "settings.h"
#include "mailbox-source.h"
#include "client.h"
#include "client-state.h"
#include "imaptest-lmtp.h"

#include <sys/time.h>

#define LMTP_DELIVERY_TIMEOUT_MSECS (1000*60)

struct imaptest_lmtp_delivery {
	struct imaptest_lmtp_delivery *prev, *next;

	struct timeval tv_start;
	struct lmtp_client *client;
	char *rcpt_to;
	struct istream *data_input;
	struct timeout *to;
};

static struct imaptest_lmtp_delivery *lmtp_deliveries = NULL;
static unsigned int lmtp_count = 0;
static time_t lmtp_last_warn;

bool imaptest_lmtp_have_deliveries(void)
{
	return lmtp_deliveries != NULL;
}

static void imaptest_lmtp_free(struct imaptest_lmtp_delivery *d)
{
	DLLIST_REMOVE(&lmtp_deliveries, d);
	lmtp_count--;
	lmtp_client_deinit(&d->client);
	if (d->data_input != NULL)
		i_stream_unref(&d->data_input);
	timeout_remove(&d->to);
	i_free(d->rcpt_to);
	i_free(d);

	if (disconnect_clients && !imaptest_has_clients())
		io_loop_stop(current_ioloop);
}

static void imaptest_lmtp_finish(void *context)
{
	struct imaptest_lmtp_delivery *d = context;

	imaptest_lmtp_free(d);
}

static void
imaptest_lmtp_rcpt_to_callback(enum lmtp_client_result result,
			       const char *reply, void *context)
{
	struct imaptest_lmtp_delivery *d = context;

	if (result != LMTP_CLIENT_RESULT_OK)
		i_error("LMTP: RCPT TO <%s> failed: %s", d->rcpt_to, reply);
}

static void
imaptest_lmtp_data_callback(enum lmtp_client_result result,
			    const char *reply, void *context)
{
	struct imaptest_lmtp_delivery *d = context;

	if (result != LMTP_CLIENT_RESULT_OK)
		i_error("LMTP: DATA for <%s> failed: %s", d->rcpt_to, reply);
	else {
		counters[STATE_LMTP]++;
		client_state_add_to_timer(STATE_LMTP, &d->tv_start);
	}
}

static void imaptest_lmtp_timeout(struct imaptest_lmtp_delivery *d)
{
	i_error("LMTP: Timeout in %s", lmtp_client_state_to_string(d->client));
	lmtp_client_close(d->client);
}

void imaptest_lmtp_send(unsigned int port, unsigned int lmtp_max_parallel_count,
			const char *rcpt_to, struct mailbox_source *source)
{
	struct lmtp_client_settings lmtp_set;
	struct imaptest_lmtp_delivery *d;
	uoff_t mail_size, vsize;
	const struct ip_addr *ip;
	time_t t;
	int tz;

	if (lmtp_count >= lmtp_max_parallel_count &&
	    lmtp_max_parallel_count != 0) {
		if (lmtp_last_warn + 30 < ioloop_time) {
			lmtp_last_warn = ioloop_time;
			i_warning("LMTP: Reached %u connections, throttling",
				  lmtp_max_parallel_count);
		}
		return;
	}

	memset(&lmtp_set, 0, sizeof(lmtp_set));
	lmtp_set.my_hostname = "localhost";
	lmtp_set.mail_from = "<>";

	d = i_new(struct imaptest_lmtp_delivery, 1);
	DLLIST_PREPEND(&lmtp_deliveries, d);
	lmtp_count++;
	d->to = timeout_add(LMTP_DELIVERY_TIMEOUT_MSECS,
			    imaptest_lmtp_timeout, d);
	d->rcpt_to = i_strdup(rcpt_to);
	gettimeofday(&d->tv_start, NULL);
	d->client = lmtp_client_init(&lmtp_set, imaptest_lmtp_finish, d);

	ip = &conf.ips[conf.ip_idx];
	if (++conf.ip_idx == conf.ips_count)
		conf.ip_idx = 0;

	if (lmtp_client_connect_tcp(d->client, LMTP_CLIENT_PROTOCOL_LMTP,
				    net_ip2addr(ip), port) < 0) {
		lmtp_client_close(d->client);
		return;
	}
	lmtp_client_add_rcpt(d->client, rcpt_to, imaptest_lmtp_rcpt_to_callback,
			     imaptest_lmtp_data_callback, d);

	mailbox_source_get_next_size(source, &mail_size, &vsize, &t, &tz);
	d->data_input = i_stream_create_limit(source->input, mail_size);
	lmtp_client_send(d->client, d->data_input);
}

void imaptest_lmtp_delivery_deinit(void)
{
	while (lmtp_deliveries != NULL)
		lmtp_client_close(lmtp_deliveries->client);
}
