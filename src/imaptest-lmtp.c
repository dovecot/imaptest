/* Copyright (c) 2007-2018 ImapTest authors, see the included COPYING file */

#include "lib.h"
#include "llist.h"
#include "ioloop.h"
#include "istream.h"
#include "time-util.h"
#include "smtp-address.h"
#include "smtp-client.h"
#include "smtp-client-connection.h"
#include "smtp-client-transaction.h"
#include "settings.h"
#include "mailbox-source.h"
#include "client.h"
#include "client-state.h"
#include "imaptest-lmtp.h"

#include <sys/time.h>

#define LMTP_DELIVERY_TIMEOUT_MSECS (1000*60)

struct imaptest_lmtp_delivery {
	struct imaptest_lmtp_delivery *prev, *next;

	struct smtp_client_connection *lmtp_conn;
	struct smtp_client_transaction *lmtp_trans;

	struct timeval tv_start;
	struct smtp_address *rcpt_to;
	struct istream *data_input;
	struct timeout *to;
};

static struct smtp_client *lmtp_client = NULL;
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
	smtp_client_connection_unref(&d->lmtp_conn);
	if (d->lmtp_trans != NULL)
		smtp_client_transaction_destroy(&d->lmtp_trans);
	if (d->data_input != NULL)
		i_stream_unref(&d->data_input);
	timeout_remove(&d->to);
	i_free(d->rcpt_to);
	i_free(d);

	if (disconnect_clients && !imaptest_has_clients())
		io_loop_stop(current_ioloop);
}

static void
imaptest_lmtp_finish(struct imaptest_lmtp_delivery *d)
{
	imaptest_lmtp_free(d);
}

static void
imaptest_lmtp_rcpt_to_callback(const struct smtp_reply *reply,
			       struct imaptest_lmtp_delivery *d)
{
	if (!smtp_reply_is_success(reply)) {
		i_error("LMTP: RCPT TO <%s> failed: %s",
			smtp_address_encode(d->rcpt_to),
			smtp_reply_log(reply));
	}
}

static void
imaptest_lmtp_data_callback(const struct smtp_reply *reply,
			       struct imaptest_lmtp_delivery *d)
{
	if (!smtp_reply_is_success(reply)) {
		i_error("LMTP: DATA for <%s> failed: %s",
			smtp_address_encode(d->rcpt_to),
			smtp_reply_log(reply));
	} else {
		counters[STATE_LMTP]++;
		client_state_add_to_timer(STATE_LMTP, &d->tv_start);
	}
}

static void
imaptest_lmtp_data_dummy_callback(const struct smtp_reply *reply ATTR_UNUSED,
				      void *context ATTR_UNUSED)
{
	/* nothing */
}

static void imaptest_lmtp_timeout(struct imaptest_lmtp_delivery *d)
{
	i_error("LMTP: Timeout in %s",
		smtp_client_transaction_get_state_name(d->lmtp_trans));
	smtp_client_connection_disconnect(d->lmtp_conn);
}

void imaptest_lmtp_send(unsigned int port, unsigned int lmtp_max_parallel_count,
			const struct smtp_address *rcpt_to,
			struct mailbox_source *source)
{
	struct smtp_client_settings lmtp_set;
	struct imaptest_lmtp_delivery *d;
	uoff_t vsize;
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

	if (lmtp_client == NULL) {
		i_zero(&lmtp_set);
		lmtp_set.my_hostname = "localhost";
		lmtp_client = smtp_client_init(&lmtp_set);
	}

	d = i_new(struct imaptest_lmtp_delivery, 1);
	DLLIST_PREPEND(&lmtp_deliveries, d);
	lmtp_count++;
	d->to = timeout_add(LMTP_DELIVERY_TIMEOUT_MSECS,
			    imaptest_lmtp_timeout, d);
	d->rcpt_to = smtp_address_clone(default_pool, rcpt_to);
	i_gettimeofday(&d->tv_start);


	ip = &conf.ips[conf.ip_idx];
	if (++conf.ip_idx == conf.ips_count)
		conf.ip_idx = 0;

	d->lmtp_conn = smtp_client_connection_create(lmtp_client,
		SMTP_PROTOCOL_LMTP, net_ip2addr(ip), port,
		SMTP_CLIENT_SSL_MODE_NONE, NULL);
	smtp_client_connection_connect(d->lmtp_conn, NULL, NULL);

	d->lmtp_trans = smtp_client_transaction_create(d->lmtp_conn,
		NULL, NULL, 0, imaptest_lmtp_finish, d);

	smtp_client_transaction_add_rcpt(d->lmtp_trans, rcpt_to, NULL,
		imaptest_lmtp_rcpt_to_callback,
		imaptest_lmtp_data_callback, d);

	d->data_input = mailbox_source_get_next(source, &vsize, &t, &tz);
	smtp_client_transaction_send(d->lmtp_trans, d->data_input,
		imaptest_lmtp_data_dummy_callback, NULL);
}

void imaptest_lmtp_delivery_deinit(void)
{
	while (lmtp_deliveries != NULL)
		smtp_client_transaction_abort(lmtp_deliveries->lmtp_trans);
	if (lmtp_client != NULL)
		smtp_client_deinit(&lmtp_client);
}
