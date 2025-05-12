/* Copyright (c) 2007-2018 ImapTest authors, see the included COPYING file */

#include "lib.h"
#include "lib-signals.h"
#include "ioloop.h"
#include "array.h"
#include "str.h"
#include "hash.h"
#include "istream.h"
#include "ostream.h"
#include "home-expand.h"
#include "smtp-address.h"
#include "dsasl-client.h"
#ifdef STATIC_OPENSSL
#  include "iostream-openssl.h"
#endif

#include "settings.h"
#include "mailbox.h"
#include "mailbox-source.h"
#include "imap-client.h"
#include "user.h"
#include "profile.h"
#include "checkpoint.h"
#include "commands.h"
#include "test-exec.h"
#include "imaptest-lmtp.h"

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

struct settings conf;
bool profile_running = FALSE;

static struct ioloop *ioloop;
static int return_value = 0;
static time_t next_checkpoint_time;
static struct ostream *results_output = NULL;
static struct timeout *to_stop;
static unsigned int final_wait_secs;

#define STATE_IS_VISIBLE(state) \
	(states[i].probability != 0)

static void print_results_header(void)
{
	string_t *str = t_str_new(128);
	unsigned int i;

	for (i = 1; i < STATE_COUNT; i++) {
		if (!STATE_IS_VISIBLE(i))
			continue;
		str_printfa(str, "\t%s count\t%s msecs",
			    states[i].name, states[i].name);
	}
	str_append_c(str, '\n');
	o_stream_nsend(results_output, str_data(str)+1, str_len(str)-1);
}

static void print_results(void)
{
	string_t *str = t_str_new(128);
	unsigned int i;

	for (i = 1; i < STATE_COUNT; i++) {
		if (!STATE_IS_VISIBLE(i))
			continue;

		str_printfa(str, "\t%d\t%d\t%lld", counters[i], timer_counts[i], timers[i]);
		timers[i] = 0;
		timer_counts[i] = 0;
	}
	str_append_c(str, '\n');
	o_stream_nsend(results_output, str_data(str)+1, str_len(str)-1);
}

static void print_timers(void)
{
	unsigned int i;

	if (isatty(STDOUT_FILENO) > 0)
		printf("\x1b[1m");

	for (i = 1; i < STATE_COUNT; i++) {
		if (!STATE_IS_VISIBLE(i))
			continue;

		printf("%4d ", timer_counts[i] == 0 ? 0 :
		       (unsigned int)(timers[i] / timer_counts[i]));
		timers[i] = 0;
		timer_counts[i] = 0;
	}
	printf("ms/cmd avg\n");
	if (isatty(STDOUT_FILENO) > 0)
		printf("\x1b[0m");
}

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
	if (profile_running)
		return;

	for (i = 1; i < STATE_COUNT; i++) {
		if (!STATE_IS_VISIBLE(i))
			continue;
		if (states[i].probability_again != 0)
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

static void print_stalled_imap_client(string_t *str, struct imap_client *client)
{
	struct command *const *cmds;
	unsigned int cmdcount;

	cmds = array_get(&client->commands, &cmdcount);
	if (client->seen_bye)
		str_append(str, "BYE, waiting for disconnect");
	else if (cmdcount == 0)
		str_append(str, states[client->client.state].name);
	else {
		str_printfa(str, "command: %u %s",
			    cmds[0]->tag, cmds[0]->cmdline);
	}
}

static void print_timeout(void *context ATTR_UNUSED)
{
#define CLIENT_STALLED_SECS(c) \
	(((c)->to != NULL || (c)->idling) ? 0 : \
	 (ioloop_time - (c)->last_io))
	struct client *const *c;
	string_t *str;
        static int rowcount = 0;
	unsigned int i, count, banner_waits, stall_count;

	if (results_output != NULL)
		print_results();
	if ((rowcount++ % 10) == 0) {
		if (rowcount > 1 && results_output == NULL) print_timers();
		print_header();
	}

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

#define SHORT_STALL_PRINT_SECS 3
	c = array_get(&clients, &count);
	for (i = 0; i < count; i++) {
		if (c[i] == NULL)
			continue;
		if (c[i]->state == STATE_BANNER)
			banner_waits++;

		unsigned int stalled_secs = CLIENT_STALLED_SECS(c[i]);
		if (stalled_secs > SHORT_STALL_PRINT_SECS)
			stall_count++;
		if (stalled_secs >= conf.stalled_disconnect_timeout &&
		    conf.stalled_disconnect_timeout > 0)
			client_disconnect(c[i]);
        }

	printf("%3d/%3d", (clients_count - banner_waits), clients_count);
	if (stall_count > 0)
		printf(" (%u stalled >%us)", stall_count, SHORT_STALL_PRINT_SECS);

	if (array_count(&clients) < conf.clients_count) {
		printf(" [%d%%]", array_count(&clients) * 100 /
		       conf.clients_count);
	}

#define LONG_STALL_PRINT_SECS 15
	printf("\n");
	str = t_str_new(256);
	for (i = 0; i < count; i++) {
		unsigned int stalled_secs =
			c[i] == NULL ? 0 : CLIENT_STALLED_SECS(c[i]);
		if (stalled_secs > LONG_STALL_PRINT_SECS &&
		    c[i]->state != STATE_BANNER) {
			struct imap_client *client = imap_client(c[i]);

			str_truncate(str, 0);
			str_printfa(str, " - %d stalled for %u secs in ",
				    c[i]->global_id,
				    (unsigned)(ioloop_time - c[i]->last_io));
			if (client != NULL)
				print_stalled_imap_client(str, client);

			stalled = TRUE;
                        printf("%s\n", str_c(str));
                }
	}

	if (ioloop_time >= next_checkpoint_time &&
	    conf.checkpoint_interval > 0) {
		struct hash_iterate_context *iter;
		char *key;
		struct mailbox_storage *storage;

		iter = hash_table_iterate_init(storages);
		while (hash_table_iterate(iter, storages, &key, &storage))
			clients_checkpoint(storage);
		hash_table_iterate_deinit(&iter);
		next_checkpoint_time = ioloop_time + conf.checkpoint_interval;
	}
}

static void print_total(void)
{
	unsigned int i;

	print_timers();
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

	if (states[STATE_IDLE].probability > 0)
		i_fatal("idle isn't currently supported with stress testing");
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

bool imaptest_has_clients(void)
{
	return clients_count > 0 || imaptest_lmtp_have_deliveries();
}

static void sig_die(const siginfo_t *si ATTR_UNUSED, void *context ATTR_UNUSED)
{
	if (!disconnect_clients) {
		/* try a nice way first by letting the clients
		   disconnect themselves */
		if (imaptest_has_clients())
			i_info("Received SIGINT - waiting for existing clients to finish");
		else {
			i_info("Received SIGINT - no running clients so stopping immediately");
			io_loop_stop(ioloop);
		}
		disconnect_clients = TRUE;
	} else {
		/* second time, die now */
		i_info("Received second SIGINT - stopping immediately");
		io_loop_stop(ioloop);
	}
	return_value = 1;
}

static void timeout_stop(void *context)
{
	if (!imaptest_has_clients())
		io_loop_stop(ioloop);
	else if (!disconnect_clients) {
		disconnect_clients = TRUE;
		timeout_remove(&to_stop);
		to_stop = timeout_add(final_wait_secs * 1000,
				      timeout_stop, context);
	} else {
		i_info("Second timeout triggered while trying to stop - stopping immediately");
		io_loop_stop(ioloop);
	}
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

static struct mailbox_source *imaptest_mailbox_source(void)
{
	struct state *state;

	state = state_find("APPEND");
	if (state->probability == 0) {
		/* we're not going to append anything, don't give an error
		   if mbox_path doesn't exist. */
		return mailbox_source_new_random(0);
	}
	if (conf.random_msg_size > 0)
		return mailbox_source_new_random(conf.random_msg_size);
	else
		return mailbox_source_new_mbox(conf.mbox_path);
}

static void imaptest_run(void)
{
	struct timeout *to;
	unsigned int i;

	next_checkpoint_time = ioloop_time + conf.checkpoint_interval;
	to = timeout_add(1000, print_timeout, NULL);
	if (!profile_running) {
		for (i = 0; i < INIT_CLIENT_COUNT && i < conf.clients_count; i++)
			client_new_random(i, mailbox_source);
	}

        io_loop_run(ioloop);

	timeout_remove(&to);
	clients_unref();

	print_total();
}

static void imaptest_run_tests(const char *path)
{
	struct test_parser *test_parser;
	const ARRAY_TYPE(test) *tests;
	struct tests_execute_context *exec_ctx;

	no_new_clients = TRUE;
	test_parser = test_parser_init(path);
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
	input = i_stream_create_fd_autoclose(&fd, (size_t)-1);
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
"imaptest [user=USER] [users=RANGE] [domains=RANGE] [userfile=FILE]\n"
"         [master=USER] [pass=PASSWORD] [mech=MECH] [seed=SEED]\n"
"         [host=HOST] [port=PORT] [mbox=MBOX] [clients=CC] [msgs=NMSG]\n"
"         [box=MAILBOX] [copybox=DESTBOX] [-] [<state>[=<n%%>[,<m%%>]]]\n"
"         [random] [no_pipelining] [no_tracking] [checkpoint=<secs>]\n"
"         [imap4rev2]\n"
"\n"
" USER = username (and domain) template, e.g. \"u%%04d\" or \"u%%04d@d%%04d\"\n"
" RANGE = range for templated usernames [1-%u] or domain names [1-%u]\n"
" FILE = file of username:passwd pairs (instead of user/users/domains)\n"
" MBOX = path to mbox from which we read mails to append.\n"
" MAILBOX = Mailbox name where to do all the work (default = INBOX).\n"
" DESTBOX = Mailbox name where to copy messages.\n"
" CC   = number of concurrent clients. [%u]\n"
" NMSG = target number of messages in the mailbox. [%u]\n"
" SEED = seed for PRNG to make test repeatable.\n"
"\n"
" -    = Sets all probabilities to 0%% except for LOGIN, LOGOUT and SELECT\n"
" <state> = Sets state's probability to n%% and repeated probability to m%%\n",
	USER_RAND, DOMAIN_RAND,
	CLIENTS_COUNT, MESSAGE_COUNT_THRESHOLD);
}
static void
parse_possible_range(const char *value, unsigned int *start_r, unsigned int *count_r)
{
	const char *endp;
	unsigned int num;

	if (str_parse_uint(value, &num, &endp) < 0 ||
	    (*endp != '\0' && *endp != '-'))
		i_fatal("Illegal number or range: %.80s", value);

	*start_r = 1;
	if (*endp == '-') {
		*start_r = num;
		if (str_to_uint(endp + 1, &num) < 0)
			i_fatal("Illegal range: %.80s", value);
	}
	*count_r = num + 1 - *start_r;
}

static
int count_printf_ints(const char *s, const char **error_r)
{
	int ints = 0;
	const char *perc = s;
	while((perc = strchr(perc, '%')) != NULL) {
		char c;
		if(perc[1] == '%') {
			perc += 2;
			continue;
		}
		while((c = *++perc), (c >= '0' && c <= '9'))
			;
		if(c != 'd' && c != 'i') {
			*error_r = "username format can only have %i or %d "
				   "format specifiers";
			return -1;
		}
		ints++;
		perc++;
	}
	return ints;
}

static inline
bool username_format_is_valid(const char *s, const char **error_r)
{
	/* All this does is ensure that there are at most 2, and only,
	 * "%d"s or "%i"s in the format string. If you mess up the '@',
	 * that's your problem. i.e. it makes our printf safe.
	 */
	int ints=count_printf_ints(s, error_r);
	if (ints < 0) {
		/* count_printf_ints sets error_r in this case. */
		return FALSE;
	} else if (ints > 2) {
		*error_r = "username format can have at most two "
			   "integer parameters";
	} else {
		return TRUE;
	}
	return FALSE;
}

int main(int argc ATTR_UNUSED, char *argv[])
{
	struct state *state;
	struct profile *profile = NULL;
	const char *error, *key, *value, *hostip = NULL, *testpath = NULL;
	unsigned int i;
	int ret, fd;

	lib_init();
	ioloop = io_loop_create();

	lib_signals_init();
	lib_signals_ignore(SIGPIPE, TRUE);
	lib_signals_set_handler(SIGINT, LIBSIG_FLAG_DELAYED, sig_die, NULL);

	conf.password = PASSWORD;
	conf.username_template = USERNAME_TEMPLATE;
	conf.host = HOST;
	conf.port = PORT;
	conf.mbox_path = home_expand(MBOX_PATH);
	conf.clients_count = CLIENTS_COUNT;
	conf.message_count_threshold = MESSAGE_COUNT_THRESHOLD;
	conf.users_rand_start = 1;
	conf.users_rand_count = USER_RAND;
	conf.domains_rand_start = 1;
	conf.domains_rand_count = DOMAIN_RAND;
	conf.mech = "LOGIN";
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
			unsigned int secs;
			const char *p;

			if (str_parse_uint(value, &secs, &p) < 0)
				i_fatal("Invalid secs: %s", value);
			if (p[0] == '\0')
				final_wait_secs = 30;
			else if (p[0] != ',' ||
				 str_to_uint(p+1, &final_wait_secs) < 0)
				i_fatal("Invalid secs: %s", value);
			to_stop = timeout_add(secs * 1000, timeout_stop, NULL);
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
		if (strcmp(*argv, "imap4rev2") == 0) {
			conf.imap4rev2 = TRUE;
			continue;
		}

		/* pass=password */
		if (strcmp(key, "pass") == 0) {
			conf.password = value;
			continue;
		}

		/* mech=auth mech */
		if (strcmp(key, "mech") == 0) {
			conf.mech = value;
			continue;
		}

		/* mbox=path */
		if (strcmp(key, "mbox") == 0) {
			conf.mbox_path = home_expand(value);
			continue;
		}
		if (strcmp(key, "random_msg_size") == 0) {
			if (str_to_uint(value, &conf.random_msg_size) < 0)
				i_fatal("Invalid random_msg_size: %s", value);
			continue;
		}

		/* clients=# */
		if (strcmp(key, "clients") == 0) {
			conf.clients_count = atoi(value);
			continue;
		}

		/* users=# */
		if (strcmp(key, "users") == 0) {
			parse_possible_range(value,
					     &conf.users_rand_start,
					     &conf.users_rand_count);
			continue;
		}
		/* domains=# */
		if (strcmp(key, "domains") == 0) {
			parse_possible_range(value,
					     &conf.domains_rand_start,
					     &conf.domains_rand_count);
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
		/* stalled_disconnect_timeout=secs */
		if (strcmp(key, "stalled_disconnect_timeout") == 0) {
			conf.stalled_disconnect_timeout = atoi(value);
			continue;
		}

		/* box=mailbox */
		if (strcmp(key, "box") == 0) {
			conf.mailbox = value;
			continue;
		}
		/* test=dir */
		if (strcmp(key, "test") == 0) {
			testpath = value;
			continue;
		}
		/* profile=path */
		if (strcmp(key, "profile") == 0) {
			profile = profile_parse(value);
			profile_running = TRUE;
			continue;
		}

		/* copybox=mailbox */
		if (strcmp(key, "copybox") == 0) {
			conf.copy_dest = value;
			continue;
		}
		if (strcmp(key, "user") == 0) {
			if (!username_format_is_valid(value, &error))
				i_fatal("invalid user format: %s", error);
			conf.username_template = value;
			continue;
		}
		if (strcmp(key, "user2") == 0) {
			conf.username2_template = value;
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
		if (strcmp(key, "hostip") == 0) {
			hostip = value;
			continue;
		}
		if (strcmp(key, "port") == 0) {
			conf.port = atoi(value);
			continue;
		}
		if (strcmp(key, "ssl_ca_file") == 0) {
			const char *output, *error;
			if (settings_parse_read_file(value, value,
						     pool_datastack_create(),
						     NULL, &output, &error) < 0)
				i_fatal("Can't read ssl_ca_file %s: %s", value, error);
			settings_file_get(output, pool_datastack_create(),
					  &conf.ssl_set.ca);
			conf.ssl_set.skip_crl_check = TRUE;
			continue;
		}
		if (strcmp(key, "output") == 0) {
			fd = creat(value, 0600);
			if (fd == -1)
				i_fatal("creat(%s) failed: %m", value);
			results_output = o_stream_create_fd_file_autoclose(&fd, 0);
			continue;
		}
		if (strcmp(key, "ssl") == 0) {
			conf.ssl = TRUE;
			if (value == NULL)
				;
			else if (strcmp(value, "any-cert") == 0)
				conf.ssl_set.allow_invalid_cert = TRUE;
			else
				i_fatal("Invalid ssl value: %s", value);
			continue;
		}

		i_fatal("Unknown arg: %s", *argv);
	}
	if (conf.mailbox == NULL)
		conf.mailbox = testpath == NULL ? "INBOX" : "imaptest";

	if (conf.username_template == NULL)
		i_fatal("Missing username");
	if (testpath != NULL && strchr(conf.username_template, '%') != NULL)
		i_fatal("Don't use %% in username with tests");

	if (hostip == NULL)
		hostip = conf.host;
	if ((ret = net_gethostbyname(hostip, &conf.ips,
				     &conf.ips_count)) != 0) {
		i_fatal("net_gethostbyname(%s) failed: %s",
			hostip, net_gethosterror(ret));
	}

	lib_set_clean_exit(TRUE);
	if (results_output != NULL)
		print_results_header();
	fix_probabilities();
	mailbox_source = imaptest_mailbox_source();
	users_init(profile, mailbox_source);
	mailboxes_init();
	clients_init();
	dsasl_clients_init();
#ifdef STATIC_OPENSSL
	ssl_iostream_openssl_init();
#endif

	i_array_init(&clients, CLIENTS_COUNT);
	if (testpath == NULL)
		imaptest_run();
	else
		imaptest_run_tests(testpath);

	imaptest_lmtp_delivery_deinit();
	clients_deinit();
	mailboxes_deinit();
	users_deinit();
	if (profile != NULL) {
		pool_unref(&profile->pool);
		profile_deinit();
	}
	mailbox_source_unref(&mailbox_source);

	if (to_stop != NULL)
		timeout_remove(&to_stop);
	if (results_output != NULL) {
		if (o_stream_flush(results_output) < 0) {
			i_error("Failed to write results: %s",
				o_stream_get_error(results_output));
		}
		o_stream_destroy(&results_output);
	}

#ifdef STATIC_OPENSSL
	ssl_iostream_openssl_deinit();
#endif
	dsasl_clients_deinit();
	lib_signals_deinit();
	io_loop_destroy(&ioloop);
	lib_deinit();
	return return_value;
}
