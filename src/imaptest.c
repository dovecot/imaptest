/* Copyright (c) 2007-2008 Timo Sirainen */

#include "lib.h"
#include "lib-signals.h"
#include "ioloop.h"
#include "array.h"
#include "str.h"
#include "hash.h"
#include "istream.h"
#include "home-expand.h"

#include "settings.h"
#include "mailbox.h"
#include "mailbox-source.h"
#include "client.h"
#include "checkpoint.h"
#include "commands.h"
#include "test-exec.h"

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

struct settings conf;

static struct ioloop *ioloop;
static int return_value = 0;
static time_t next_checkpoint_time;

#define STATE_IS_VISIBLE(state) \
	(states[i].probability != 0)

static void print_header(void)
{
	unsigned int i;
	bool have_agains = FALSE;

	for (i = 1; i < STATE_COUNT; i++) {
		if (!STATE_IS_VISIBLE(i))
			continue;
		printf("%s ", states[i].short_name);
	}
	printf("\n");
	for (i = 1; i < STATE_COUNT; i++) {
		if (!STATE_IS_VISIBLE(i))
			continue;
		if (states[i].probability_again)
			have_agains = TRUE;
		printf("%3d%% ", states[i].probability);
	}
	printf("\n");

	if (have_agains) {
		for (i = 1; i < STATE_COUNT; i++) {
			if (!STATE_IS_VISIBLE(i))
				continue;
			if (states[i].probability_again == 0)
				printf("     ");
			else
				printf("%3d%% ", states[i].probability_again);
		}
		printf("\n");
	}
}

static void print_timeout(void *context ATTR_UNUSED)
{
	struct client *const *c;
	string_t *str;
        static int rowcount = 0;
	unsigned int i, count, banner_waits, stall_count;

        if ((rowcount++ % 10) == 0)
                print_header();

        for (i = 1; i < STATE_COUNT; i++) {
		if (!STATE_IS_VISIBLE(i))
			continue;
		printf("%4d ", counters[i]);
		total_counters[i] += counters[i];
		counters[i] = 0;
        }

	stalled = FALSE;
	banner_waits = 0;
	stall_count = 0;

	c = array_get(&clients, &count);
	for (i = 0; i < count; i++) {
		if (c[i] != NULL && c[i]->state == STATE_BANNER) {
			banner_waits++;

			if (c[i]->last_io < ioloop_time - 15) {
				stall_count++;
				stalled = TRUE;
			}
                }
        }

	printf("%3d/%3d", (clients_count - banner_waits), clients_count);
	if (stall_count > 0)
		printf(" (%u stalled)", stall_count);

	if (array_count(&clients) < conf.clients_count) {
		printf(" [%d%%]", array_count(&clients) * 100 /
		       conf.clients_count);
	}

#define STALL_PRINT_SECS 15
	printf("\n");
	str = t_str_new(256);
	for (i = 0; i < count; i++) {
		if (c[i] != NULL && c[i]->state != STATE_BANNER &&
		    c[i]->to == NULL &&
		    c[i]->last_io < ioloop_time - STALL_PRINT_SECS) {
			struct command *const *cmds;
			unsigned int cmdcount;

			str_truncate(str, 0);
			str_printfa(str, " - %d stalled for %u secs in ",
				    c[i]->global_id,
				    (unsigned)(ioloop_time - c[i]->last_io));
			cmds = array_get(&c[i]->commands, &cmdcount);
			if (cmdcount == 0)
				str_append(str, states[c[i]->state].name);
			else {
				str_printfa(str, "command: %u %s",
					    cmds[0]->tag, cmds[0]->cmdline);
			}

			stalled = TRUE;
                        printf("%s\n", str_c(str));
                }
	}

	if (ioloop_time >= next_checkpoint_time &&
	    conf.checkpoint_interval > 0) {
		struct hash_iterate_context *iter;
		void *key, *value;

		iter = hash_table_iterate_init(storages);
		while (hash_table_iterate(iter, &key, &value)) {
			struct mailbox_storage *storage = value;

			clients_checkpoint(storage);
		}
		hash_table_iterate_deinit(&iter);
		next_checkpoint_time = ioloop_time + conf.checkpoint_interval;
	}
}

static void print_total(void)
{
        unsigned int i;

	printf("\nTotals:\n");
	print_header();

        for (i = 1; i < STATE_COUNT; i++) {
		if (!STATE_IS_VISIBLE(i))
			continue;

		total_counters[i] += counters[i];
		printf("%4d ", total_counters[i]);
	}
	printf("\n");
}

static void fix_probabilities(void)
{
	unsigned int i;

	if (conf.copy_dest == NULL)
		states[STATE_COPY].probability = 0;
	if (conf.checkpoint_interval == 0)
		states[STATE_CHECKPOINT].probability = 0;
	else
		states[STATE_CHECKPOINT].probability = 100;

	if (conf.master_user != NULL) {
		states[STATE_AUTHENTICATE].probability = 100;
		states[STATE_LOGIN].probability = 0;
	} else if (states[STATE_LOGIN].probability != 100) {
		states[STATE_AUTHENTICATE].probability =
			100 - states[STATE_LOGIN].probability;
	} else if (states[STATE_AUTHENTICATE].probability != 0) {
		states[STATE_LOGIN].probability =
			100 - states[STATE_AUTHENTICATE].probability;
	}

	for (i = STATE_LIST; i <= STATE_LOGOUT; i++) {
		if (states[i].probability > 0)
			break;
	}
	if (i > STATE_LOGOUT)
		i_fatal("Invalid probabilities");
}

static void sig_die(const siginfo_t *si ATTR_UNUSED, void *context ATTR_UNUSED)
{
	if (!disconnect_clients) {
		/* try a nice way first by letting the clients
		   disconnect themselves */
		disconnect_clients = TRUE;
	} else {
		/* second time, die now */
		io_loop_stop(ioloop);
	}
	return_value = 1;
}

static void timeout_stop(void *context ATTR_UNUSED)
{
	disconnect_clients = TRUE;
}

static struct state *state_find(const char *name)
{
	unsigned int i;

	for (i = 0; i < STATE_COUNT; i++) {
		if (strcasecmp(states[i].name, name) == 0 ||
		    strcasecmp(states[i].short_name, name) == 0)
			return &states[i];
	}
	return NULL;
}

static void clients_unref(void)
{
	struct client *const *c;
	unsigned int i, count;

	c = array_get(&clients, &count);
	for (i = 0; i < count; i++) {
		if (c[i] != NULL)
			client_unref(c[i], FALSE);
        }
}

static void imaptest_run(void)
{
	struct timeout *to;
	unsigned int i;

	next_checkpoint_time = ioloop_time + conf.checkpoint_interval;
	mailbox_source = mailbox_source_new(conf.mbox_path);
	to = timeout_add(1000, print_timeout, NULL);
	for (i = 0; i < INIT_CLIENT_COUNT && i < conf.clients_count; i++)
		client_new(i, mailbox_source);

        io_loop_run(ioloop);

	timeout_remove(&to);
	clients_unref();
	mailbox_source_unref(&mailbox_source);

	print_total();
}

static void imaptest_run_tests(const char *dir)
{
	struct test_parser *test_parser;
	const ARRAY_TYPE(test) *tests;
	struct tests_execute_context *exec_ctx;

	no_new_clients = TRUE;
	test_parser = test_parser_init(dir);
	tests = test_parser_get_tests(test_parser);

	exec_ctx = tests_execute(tests);
	io_loop_run(ioloop);

	clients_unref();
	if (!tests_execute_done(&exec_ctx))
		return_value = 2;

	test_parser_deinit(&test_parser);
}

static void conf_read_usernames(const char *path)
{
	struct istream *input;
	int fd;
	const char *line;

	i_array_init(&conf.usernames, 32);
	fd = open(path, O_RDONLY);
	if (fd == -1)
		i_fatal("open(%s) failed: %m", path);
	input = i_stream_create_fd(fd, (size_t)-1, TRUE);
	i_stream_set_return_partial_line(input, TRUE);
	while ((line = i_stream_read_next_line(input)) != NULL) {
		if (*line != '\0' && *line != ':') {
			line = i_strdup(line);
			array_append(&conf.usernames, &line, 1);
		}
	}
	i_stream_destroy(&input);

	if (array_count(&conf.usernames) == 0)
		i_fatal("No usernames in file %s", path);
}

static void print_help(void)
{
	printf(
"imaptest [user=USER] [userfile=FILE] [master=USER] [pass=PASSWORD]\n"
"         [host=HOST] [port=PORT] [mbox=MBOX] [clients=CC] [msgs=NMSG]\n"
"         [box=MAILBOX] [copybox=DESTBOX] [-] [<state>[=<n%%>[,<m%%>]]]\n"
"         [random] [no_pipelining] [no_tracking] [checkpoint=<secs>]\n"
"\n"
" USER = template for username. \"u%%04d\" will generate users \"u0001\" to\n"
"        \"u0099\". \"u%%04d@d%%04d\" will generate also \"d0001\" to \"d0099\".\n"
" MBOX = path to mbox from which we read mails to append.\n"
" MAILBOX = Mailbox name where to do all the work (default = INBOX).\n"
" DESTBOX = Mailbox name where to copy messages.\n"
" CC   = number of concurrent clients. [%u]\n"
" NMSG = target number of messages in the mailbox. [%u]\n"
"\n"
" -    = Sets all probabilities to 0%% except for LOGIN, LOGOUT and SELECT\n"
" <state> = Sets state's probability to n%% and repeated probability to m%%\n",
	CLIENTS_COUNT, MESSAGE_COUNT_THRESHOLD);
}

int main(int argc ATTR_UNUSED, char *argv[])
{
	struct timeout *to_stop;
	struct state *state;
	const char *key, *value, *testdir = NULL;
	unsigned int i;
	int ret;

	lib_init();
	ioloop = io_loop_create();

	lib_signals_init();
        lib_signals_set_handler(SIGINT, TRUE, sig_die, NULL);

	conf.password = PASSWORD;
	conf.username_template = USERNAME_TEMPLATE;
	conf.host = HOST;
	conf.port = PORT;
	conf.mbox_path = home_expand(MBOX_PATH);
	conf.clients_count = CLIENTS_COUNT;
	conf.message_count_threshold = MESSAGE_COUNT_THRESHOLD;
	to_stop = NULL;

	for (argv++; *argv != NULL; argv++) {
		value = strchr(*argv, '=');
		key = value == NULL ? *argv :
			t_strdup_until(*argv, value);
		if (value != NULL) value++;

		if (strcmp(*argv, "-h") == 0 ||
		    strcmp(*argv, "--help") == 0) {
			print_help();
			return 0;
		}
		if (strcmp(key, "secs") == 0) {
			to_stop = timeout_add(atoi(value) * 1000,
					      timeout_stop, NULL);
			continue;
		}
		if (strcmp(key, "seed") == 0) {
			srand(atoi(value));
			continue;
		}

		if (strcmp(*argv, "-") == 0) {
			for (i = STATE_LOGIN+1; i < STATE_LOGOUT; i++) {
				if (i != STATE_SELECT)
					states[i].probability = 0;
			}
			continue;
		}

		state = state_find(key);
		if (state != NULL) {
			/* [<probability>[,<probability_again>]] */
			const char *p;

			if (value == NULL) {
				state->probability = 100;
				continue;
			}
			p = strchr(value, ',');
			if (p != NULL)
				value = t_strdup_until(value, p++);

			state->probability = atoi(value);
			if (p != NULL)
				state->probability_again = atoi(p);
			continue;
		}

		if (strcmp(*argv, "random") == 0) {
			conf.random_states = TRUE;
			continue;
		}
		if (strcmp(*argv, "no_pipelining") == 0) {
			conf.no_pipelining = TRUE;
			continue;
		}
		if (strcmp(*argv, "no_tracking") == 0) {
			conf.no_tracking = TRUE;
			continue;
		}
		if (strcmp(*argv, "disconnect_quit") == 0) {
			conf.disconnect_quit = TRUE;
			continue;
		}
		if (strcmp(*argv, "error_quit") == 0) {
			conf.error_quit = TRUE;
			continue;
		}
		if (strcmp(*argv, "rawlog") == 0) {
			conf.rawlog = TRUE;
			continue;
		}
		if (strcmp(*argv, "own_msgs") == 0) {
			conf.own_msgs = TRUE;
			continue;
		}
		if (strcmp(*argv, "own_flags") == 0) {
			conf.own_flags = TRUE;
			continue;
		}
		if (strcmp(*argv, "qresync") == 0) {
			conf.qresync = TRUE;
			continue;
		}

		/* pass=password */
		if (strcmp(key, "pass") == 0) {
			conf.password = value;
			continue;
		}

		/* mbox=path */
		if (strcmp(key, "mbox") == 0) {
			conf.mbox_path = home_expand(value);
			continue;
		}

		/* clients=# */
		if (strcmp(key, "clients") == 0) {
			conf.clients_count = atoi(value);
			continue;
		}

		/* msgs=# */
		if (strcmp(key, "msgs") == 0) {
			conf.message_count_threshold = atoi(value);
			continue;
		}
		/* checkpoint=# */
		if (strcmp(key, "checkpoint") == 0) {
			conf.checkpoint_interval = atoi(value);
			continue;
		}

		/* box=mailbox */
		if (strcmp(key, "box") == 0) {
			conf.mailbox = value;
			continue;
		}
		/* test=dir */
		if (strcmp(key, "test") == 0) {
			testdir = value;
			continue;
		}

		/* copybox=mailbox */
		if (strcmp(key, "copybox") == 0) {
			conf.copy_dest = value;
			continue;
		}
		if (strcmp(key, "user") == 0) {
			conf.username_template = value;
			continue;
		}
		if (strcmp(key, "userfile") == 0) {
			conf_read_usernames(value);
			continue;
		}
		if (strcmp(key, "master") == 0) {
			conf.master_user = value;
			continue;
		}
		if (strcmp(key, "host") == 0) {
			conf.host = value;
			continue;
		}
		if (strcmp(key, "port") == 0) {
			conf.port = atoi(value);
			continue;
		}

		printf("Unknown arg: %s\n", *argv);
		return 1;
	}
	if (conf.mailbox == NULL)
		conf.mailbox = testdir == NULL ? "INBOX" : "imaptest";

	if (conf.username_template == NULL)
		i_fatal("Missing username");
	if (testdir != NULL && strchr(conf.username_template, '%') != NULL) {
		printf("Don't use %% in username with tests\n");
		return 1;
	}
	if (!conf.no_tracking && strchr(conf.username_template, '%') != NULL) {
		printf("State tracking is broken currently if you use %% in username.\n"
		       "Either drop it or add no_tracking parameter.\n");
		return 1;
	}

	if ((ret = net_gethostbyname(conf.host, &conf.ips,
				     &conf.ips_count)) != 0) {
		i_error("net_gethostbyname(%s) failed: %s",
			conf.host, net_gethosterror(ret));
		return 1;
	}

	fix_probabilities();
	mailboxes_init();
	clients_init();

	i_array_init(&clients, CLIENTS_COUNT);
	if (testdir == NULL)
		imaptest_run();
	else
		imaptest_run_tests(testdir);
	clients_deinit();
	mailboxes_deinit();

	if (to_stop != NULL)
		timeout_remove(&to_stop);

	lib_signals_deinit();
	io_loop_destroy(&ioloop);
	lib_deinit();
	return return_value;
}
