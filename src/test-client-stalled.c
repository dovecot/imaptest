/* Copyright (c) ImapTest authors, see top-level COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "array.h"
#include "settings.h"
#include "client.h"
#include "imap-client.h"
#include "user.h"
#include "mailbox.h"
#include "mailbox-source.h"
#include "test-common.h"

struct settings conf;
bool profile_running = FALSE;

/* Mock net_connect_ip to return a real (but unconnected) socket.
   This allows using real i_stream_create_fd() etc. without real network.
   Since we link against libdovecot, we can provide our own version of this
   function to override the one in the library for this test. */
int net_connect_ip(const struct ip_addr *ip, in_port_t port, const struct ip_addr *my_ip)
{
	return socket(AF_INET, SOCK_STREAM, 0);
}

/* These are needed by imap-client.c and other files but are defined in imaptest.c */
bool imaptest_has_clients(void) { return FALSE; }
void sig_die(int signo ATTR_UNUSED, void *context ATTR_UNUSED) { exit(1); }
void error_quit(void) { exit(1); }

static void test_stalled_client_reassignment(void)
{
	struct user *user;
	struct imap_client *c1, *c2, *c3;
	struct ioloop *ioloop;
	struct mailbox_source *source;

	test_begin("stalled client index reassignment");

	ioloop = io_loop_create();

	conf.clients_count = 10;
	conf.ips_count = 1;
	conf.ips = i_new(struct ip_addr, 1);
	conf.mailbox = "INBOX";

	clients_init();
	mailboxes_init();

	source = mailbox_source_new_random(1024);
	users_init(NULL, source);
	user = user_get("testuser", source);

	/* 1. Add a client at index 0 */
	if (imap_client_new(0, user, NULL, &c1) < 0)
		i_fatal("imap_client_new 1 failed");

	test_assert(array_count(&clients) == 1);
	test_assert(array_idx_elem(&clients, 0) == &c1->client);

	/* 2. Set stalled = TRUE, then try to init another client at index 0.
	   This simulates clients_unstalled() trying to reuse index 0. */
	stalled = TRUE;
	/* In the fixed code, client_init should have found that index 0 is occupied,
	   found index 1 is free, and appended index 1 to stalled_clients. */
	if (imap_client_new(0, user, NULL, &c2) != -1)
		i_fatal("imap_client_new 2 should have stalled and returned -1");

	const unsigned int *stalled_idxs;
	unsigned int stalled_count;
	stalled_idxs = array_get(&stalled_clients, &stalled_count);
	test_assert(stalled_count == 1);
	test_assert(stalled_idxs[0] == 1);

	/* 3. Now let's occupy index 1 as well */
	stalled = FALSE;
	if (imap_client_new(1, user, NULL, &c3) < 0)
		i_fatal("imap_client_new 3 failed");

	test_assert(array_count(&clients) == 2);
	test_assert(array_idx_elem(&clients, 1) == &c3->client);

	/* 4. Now try to stall index 0 again. It should find index 2. */
	stalled = TRUE;
	if (imap_client_new(0, user, NULL, &c2) != -1)
		i_fatal("imap_client_new 4 should have stalled and returned -1");

	stalled_idxs = array_get(&stalled_clients, &stalled_count);
	test_assert(stalled_count == 2);
	test_assert(stalled_idxs[1] == 2);

	client_unref(&c1->client, FALSE);
	client_unref(&c3->client, FALSE);

	users_deinit();
	mailbox_source_unref(&source);
	mailboxes_deinit();
	clients_deinit();
	array_free(&clients);
	i_free(conf.ips);

	io_loop_destroy(&ioloop);

	test_end();
}

static void test_nonstalled_client_reassignment(void)
{
	struct user *user;
	struct imap_client *c1, *c2;
	struct ioloop *ioloop;
	struct mailbox_source *source;

	test_begin("non-stalled client index reassignment");

	ioloop = io_loop_create();

	conf.clients_count = 10;
	conf.ips_count = 1;
	conf.ips = i_new(struct ip_addr, 1);
	conf.mailbox = "INBOX";

	clients_init();
	mailboxes_init();

	source = mailbox_source_new_random(1024);
	users_init(NULL, source);
	user = user_get("testuser", source);

	/* 1. Add a client at index 0 */
	if (imap_client_new(0, user, NULL, &c1) < 0)
		i_fatal("imap_client_new 1 failed");

	test_assert(array_count(&clients) == 1);
	test_assert(c1->client.idx == 0);

	/* 2. With stalled = FALSE, request index 0 which is occupied.
	   client_init should find index 1 free and create the client there. */
	stalled = FALSE;
	if (imap_client_new(0, user, NULL, &c2) < 0)
		i_fatal("imap_client_new 2 failed");

	test_assert(array_count(&clients) == 2);
	test_assert(c2->client.idx == 1);
	test_assert(array_idx_elem(&clients, 1) == &c2->client);

	/* 3. Verify stalled_clients array is empty - nothing was stalled */
	const unsigned int *stalled_idxs;
	unsigned int stalled_count;
	stalled_idxs = array_get(&stalled_clients, &stalled_count);
	test_assert(stalled_count == 0);

	client_unref(&c1->client, FALSE);
	client_unref(&c2->client, FALSE);

	users_deinit();
	mailbox_source_unref(&source);
	mailboxes_deinit();
	clients_deinit();
	array_free(&clients);
	i_free(conf.ips);

	io_loop_destroy(&ioloop);

	test_end();
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_stalled_client_reassignment,
		test_nonstalled_client_reassignment,
		NULL
	};
	return test_run(test_functions);
}
