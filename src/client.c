/* Copyright (c) 2007-2018 ImapTest authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "array.h"
#include "istream.h"
#include "ostream.h"
#include "iostream-rawlog.h"
#include "iostream-ssl.h"
#include "str.h"
#include "imap-parser.h"

#include "imap-client.h"
#include "pop3-client.h"
#include "imap-util.h"
#include "settings.h"
#include "mailbox.h"
#include "mailbox-state.h"
#include "commands.h"
#include "checkpoint.h"
#include "profile.h"
#include "search.h"
#include "test-exec.h"
#include "client.h"

#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

int clients_count = 0;
unsigned int total_disconnects = 0;
ARRAY_TYPE(client) clients;
ARRAY(unsigned int) stalled_clients;
bool stalled = FALSE, disconnect_clients = FALSE, scripted_tests_running = FALSE;

static unsigned int client_min_free_idx = 0;
static unsigned int global_id_counter = 0;
static struct ssl_iostream_context *ssl_ctx = NULL;

static void client_input(struct client *client)
{
	client->last_io = ioloop_time;

	switch (i_stream_read(client->input)) {
	case 0:
		return;
	case -1:
		/* disconnected */
		if (client->input->stream_errno != 0 &&
		    client->input->stream_errno != EPIPE &&
		    !client->logout_sent)
			e_error(client->event, "Client disconnected: %s",
				i_stream_get_error(client->input));
		if (client->v.disconnected != NULL) {
			if (!client->v.disconnected(client))
				return;
		}
		client_unref(client, TRUE);
		return;
	case -2:
		/* buffer full */
		e_error(client->event, "line too long");
		client_unref(client, TRUE);
		return;
	}
	client->refcount++;
	client->v.input(client);
	if (do_rand(STATE_DISCONNECT)) {
		/* random disconnection */
		counters[STATE_DISCONNECT]++;
		client_unref(client, TRUE);
	} else {
		if (client->input->closed)
			client_unref(client, TRUE);
	}
	client_unref(client, TRUE);
}

void client_input_stop(struct client *client)
{
	if (client->io != NULL)
		io_remove(&client->io);
}

void client_input_continue(struct client *client)
{
	if (client->io == NULL && !client->input->closed)
		client->io = io_add_istream(client->input, client_input, client);
}

static void client_delay_timeout(struct client *client)
{
	i_assert(client->io == NULL);

	client->delayed = FALSE;
	client->last_io = ioloop_time;

	timeout_remove(&client->to);
	client_input_continue(client);
}

void client_delay(struct client *client, unsigned int msecs)
{
	if (client->input->closed) {
		/* we're already disconnected and client->to is set */
		return;
	}
	i_assert(client->to == NULL);

	client->delayed = TRUE;
	io_remove(&client->io);
	client->to = timeout_add(msecs, client_delay_timeout, client);
}

static int client_output(struct client *client)
{
	int ret;

	o_stream_cork(client->output);
	ret = o_stream_flush(client->output);
	client->last_io = ioloop_time;

	if (ret > 0) {
		if (client->v.output(client) < 0)
			ret = -1;
	}
	o_stream_uncork(client->output);
	if (ret < 0)
		client_unref(client, TRUE);
        return ret;
}

void client_rawlog_init(struct client *client)
{
	if (!conf.rawlog)
		return;

	client->pre_rawlog_input = client->input;
	client->pre_rawlog_output = client->output;

	if (iostream_rawlog_create_path(client->event, "rawlog",
			t_strdup_printf("rawlog.%u", client->global_id),
			&client->input, &client->output) != 0)
		client->rawlog_fd = o_stream_get_fd(client->output);
	client->rawlog_input = client->input;
	client->rawlog_output = client->output;
}

void client_rawlog_deinit(struct client *client)
{
	if (client->rawlog_input == NULL)
		return;

	i_assert(client->rawlog_input == client->input);
	i_assert(client->rawlog_output == client->output);
	i_stream_ref(client->pre_rawlog_input);
	o_stream_ref(client->pre_rawlog_output);
	i_stream_destroy(&client->rawlog_input);
	o_stream_destroy(&client->rawlog_output);
	client->input = client->pre_rawlog_input;
	client->output = client->pre_rawlog_output;
}

static void client_wait_connect(struct client *client)
{
	const char *error;
	int err;

	err = net_geterror(client->fd);
	if (err != 0) {
		e_error(client->event, "connect() failed: %s", strerror(err));
		client_unref(client, TRUE);
		return;
	}

	/* remove before ssl handshake */
	io_remove(&client->io);

	if (conf.ssl) {
		if (ssl_ctx == NULL) {
			if (ssl_iostream_context_init_client(&conf.ssl_set, &ssl_ctx, &error) < 0)
				i_fatal("Failed to initialize SSL context: %s", error);
		}
		if (io_stream_create_ssl_client(ssl_ctx, conf.host, NULL, 0,
						&client->input, &client->output,
						&client->ssl_iostream, &error) < 0)
			i_fatal("Couldn't create SSL iostream: %s", error);
		(void)ssl_iostream_handshake(client->ssl_iostream);
	}
	client_rawlog_init(client);

	client->io = io_add_istream(client->input, client_input, client);
	client->v.connected(client);
}

static struct client *
client_new_full(unsigned int i, struct user *user, struct user_client *uc)
{
	struct imap_client *imap_c;
	struct pop3_client *pop3_c;

	if (client_min_free_idx == i)
		client_min_free_idx++;

	if (uc == NULL || uc->profile == NULL ||
	    strcmp(uc->profile->protocol, "imap") == 0) {
		if (imap_client_new(i, user, uc, &imap_c) < 0)
			return NULL;
		return &imap_c->client;
	} else if (strcmp(uc->profile->protocol, "pop3") == 0) {
		if (pop3_client_new(i, user, uc, &pop3_c) < 0)
			return NULL;
		return &pop3_c->client;
	} else
		i_unreached();
}

struct client *client_new_user(struct user *user)
{
	struct client *const *clientp;
	struct user_client *uc;

	if (!user_get_new_client_profile(user, &uc))
		return NULL;
	while (client_min_free_idx < conf.clients_count) {
		clientp = array_idx_get_space(&clients, client_min_free_idx);
		if (*clientp == NULL)
			return client_new_full(client_min_free_idx, user, uc);
		client_min_free_idx++;
	}
	return NULL;
}

struct client *client_new_random(unsigned int i, struct mailbox_source *source)
{
	struct user *user;
	struct user_client *uc;

	if (!user_get_random(source, &user))
		return NULL;
	if (!user_get_new_client_profile(user, &uc))
		return NULL;
	return client_new_full(i, user, uc);
}

int client_init(struct client *client, unsigned int idx,
		struct user *user, struct user_client *uc)
{
	const struct ip_addr *ip;
	int fd;

	i_assert(idx >= array_count(&clients) ||
		 *(struct client **)array_idx(&clients, idx) == NULL);
	if (stalled) {
		array_append(&stalled_clients, &idx, 1);
		return -1;
	}

	client->refcount = 1;
	client->idx = idx;
	client->user = user;
	client->user_client = uc;
	client->global_id = ++global_id_counter;
	client->event = event_create(NULL);
	event_set_append_log_prefix(client->event,
		t_strdup_printf("%s[%u]: ", user->username,
				client->global_id));

	ip = &conf.ips[conf.ip_idx];
	fd = net_connect_ip(ip, client->port, NULL);
	if (++conf.ip_idx == conf.ips_count)
		conf.ip_idx = 0;

	if (fd < 0) {
		e_error(client->event, "connect() failed: %m");
		event_unref(&client->event);
		return -1;
	}

	client->fd = fd;
	client->rawlog_fd = -1;
	client->input = i_stream_create_fd(fd, (size_t)-1);
	client->output = o_stream_create_fd(fd, (size_t)-1);
	i_stream_set_name(client->input, t_strdup_printf("client %u", idx));
	o_stream_set_name(client->output, t_strdup_printf("client %u", idx));
	o_stream_set_no_error_handling(client->output, TRUE);
	o_stream_set_flush_callback(client->output, client_output, client);
	client->io = io_add(fd, IO_WRITE, client_wait_connect, client);
        client->last_io = ioloop_time;

	clients_count++;
	user_add_client(user, client);
        array_idx_set(&clients, idx, &client);
	return 0;
}

void client_logout(struct client *client)
{
	client->state = STATE_LOGOUT;
	client->logout_sent = TRUE;
	if (client->user_client != NULL)
		client->user_client->last_logout = ioloop_time;
	client->v.logout(client);
}

void client_disconnect(struct client *client)
{
	client->disconnected = TRUE;

	i_stream_close(client->input);
	o_stream_close(client->output);

	if (client->io != NULL)
		io_remove(&client->io);
	if (client->to != NULL)
		timeout_remove(&client->to);
	client->to = timeout_add(0, client_input, client);
}

static void clients_unstalled(struct mailbox_source *source)
{
	const unsigned int *indexes;
	unsigned int count, i, restart[3], take;

	indexes = array_get(&stalled_clients, &count);
	take = I_MIN(count, N_ELEMENTS(restart));
	if (!take)
		return;

	/* Safely remove the indexes from the stalled array before
	 * restarting clients. This is because client_new_random() may
	 * re-add this index to the stalled_clients, which may reallocate
	 * the array and invalidate indexes pointer. */
	memcpy(restart, indexes, take * sizeof(restart[0]));
	array_delete(&stalled_clients, 0, take);

	for (i = 0; i < take; i++)
		(void)client_new_random(restart[i], source);
}

bool client_unref(struct client *client, bool reconnect)
{
	struct mailbox_source *source = client->user->mailbox_source;
	unsigned int idx = client->idx;

	i_assert(client->refcount > 0);
	if (--client->refcount > 0)
		return TRUE;

	total_disconnects++;

	if (--clients_count == 0)
		stalled = FALSE;
	array_idx_clear(&clients, idx);
	if (client_min_free_idx > idx)
		client_min_free_idx = idx;

	client->v.free(client);

	o_stream_destroy(&client->output);
	i_stream_destroy(&client->input);
	if (client->ssl_iostream != NULL)
		ssl_iostream_destroy(&client->ssl_iostream);
	if (client->io != NULL)
		io_remove(&client->io);
	if (client->to != NULL)
		timeout_remove(&client->to);
	if (close(client->fd) < 0)
		e_error(client->event, "close(client) failed: %m");
	user_remove_client(client->user, client);

	if (disconnect_clients && !imaptest_has_clients())
		io_loop_stop(current_ioloop);
	else if (io_loop_is_running(current_ioloop) && !scripted_tests_running &&
		 !disconnect_clients && reconnect) {
		if (client->logout_sent) {
			/* user successfully logged out, get another
			   random user */
			if (client->user_client == NULL ||
			    client->user_client->profile == NULL)
				client_new_random(idx, source);
		} else {
			/* server disconnected user. reconnect back with the
			   same user. this is especially important when testing
			   with profiles since real clients reconnect when they
			   get disconnected (e.g. server crash/restart). */
			client_new_user(client->user);
		}

		if (!stalled && (client->user_client == NULL ||
				 client->user_client->profile == NULL))
			clients_unstalled(source);
	}
	event_unref(&client->event);
	i_free(client);
	return FALSE;
}

int client_send_more_commands(struct client *client)
{
	int ret;

	o_stream_cork(client->output);
	ret = client->v.send_more_commands(client);
	o_stream_uncork(client->output);
	return ret;
}

unsigned int clients_get_random_idx(void)
{
	struct client *const *c;
	unsigned int i, idx, count;

	/* first try randomly */
	c = array_get(&clients, &count);
	for (i = 0; i < 100; i++) {
		idx = i_rand_limit(count);
		if (c[idx] != NULL)
			return idx;
	}
	/* then just try anything */
	for (i = 0; i < count; i++) {
		if (c[i] != NULL)
			return i;
	}
	i_unreached();
	return 0;
}

void clients_init(void)
{
	i_array_init(&stalled_clients, CLIENTS_COUNT);
}

void clients_deinit(void)
{
	if (ssl_ctx != NULL)
		ssl_iostream_context_unref(&ssl_ctx);
	array_free(&stalled_clients);
}
