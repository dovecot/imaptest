/* Copyright (c) 2013 Timo Sirainen */

#include "lib.h"
#include "ioloop.h"
#include "str.h"
#include "imap-arg.h"
#include "imap-quote.h"
#include "client.h"
#include "mailbox.h"
#include "mailbox-source.h"
#include "commands.h"
#include "imaptest-lmtp.h"
#include "profile.h"

#include <stdlib.h>
#include <math.h>

#define RANDU (rand() / (double)RAND_MAX)
#define RANDN2(mu, sigma) \
	(mu + (rand()%2 ? -1.0 : 1.0) * sigma * pow(-log(0.99999*RANDU), 0.5))
#define weighted_rand(n) \
	(int)RANDN2(n, n/2)

static void user_set_timeout(struct user *user);

static void client_profile_init_mailbox(struct client *client)
{
	struct user_mailbox_cache *cache;

	cache = user_get_mailbox_cache(client->user, client->storage->name);
	if (cache->uidvalidity != 0)
		return;

	cache->uidvalidity = client->storage->uidvalidity;
	cache->uidnext = client->view->select_uidnext;
	cache->highest_modseq = client->view->highest_modseq;

	cache->last_action_uid = cache->uidnext;
}

static void
client_profile_send_missing_creates(struct client *client)
{
	if (client_mailboxes_list_find(client, PROFILE_MAILBOX_SPAM) == NULL)
		command_send(client, "CREATE \""PROFILE_MAILBOX_SPAM"\"", state_callback);
	if (client_mailboxes_list_find(client, PROFILE_MAILBOX_DRAFTS) == NULL)
		command_send(client, "CREATE \""PROFILE_MAILBOX_DRAFTS"\"", state_callback);
	if (client_mailboxes_list_find(client, PROFILE_MAILBOX_SENT) == NULL)
		command_send(client, "CREATE \""PROFILE_MAILBOX_SENT"\"", state_callback);
}

int client_profile_send_more_commands(struct client *client)
{
	string_t *cmd = t_str_new(128);

	if (array_count(&client->commands) > 0)
		return 0;

	switch (client->login_state) {
	case LSTATE_NONAUTH:
		str_append(cmd, "LOGIN ");
		imap_append_astring(cmd, client->user->username);
		str_append_c(cmd, ' ');
		imap_append_astring(cmd, client->user->password);
		client->state = STATE_LOGIN;
		break;
	case LSTATE_AUTH:
		if (!array_is_created(&client->mailboxes_list)) {
			str_append(cmd, "LIST \"\" *");
			client->state = STATE_LIST;
			client_mailboxes_list_begin(client);
		} else {
			client_profile_send_missing_creates(client);
			str_append(cmd, "SELECT ");
			imap_append_astring(cmd, client->storage->name);
			client->state = STATE_SELECT;
		}
		break;
	case LSTATE_SELECTED:
		client_profile_init_mailbox(client);
		str_append(cmd, "IDLE");
		client->state = STATE_IDLE;
		break;
	}
	command_send(client, str_c(cmd), state_callback);
	return 0;
}

static void client_profile_handle_exists(struct client *client)
{
	struct user_mailbox_cache *cache;
	const char *cmd;

	/* fetch new messages */
	cache = user_get_mailbox_cache(client->user, client->storage->name);
	cmd = t_strdup_printf("UID FETCH %u:* (%s)", cache->uidnext,
			      client->profile->imap_fetch_immediate);
	client->state = STATE_FETCH;
	command_send(client, cmd, state_callback);
}

static void client_profile_handle_fetch(struct client *client,
					const struct imap_arg *list_arg)
{
	struct user_mailbox_cache *cache;
	const struct imap_arg *args;
	const char *name, *value;
	uint32_t uid;

	if (!imap_arg_get_list(list_arg, &args))
		return;
	while (!IMAP_ARG_IS_EOL(args)) {
		if (!imap_arg_get_atom(args, &name))
			return;
		args++;
		if (IMAP_ARG_IS_EOL(args))
			return;

		if (strcasecmp(name, "UID") == 0) {
			if (!imap_arg_get_atom(args, &value) ||
			    str_to_uint32(value, &uid) < 0)
				return;

			cache = user_get_mailbox_cache(client->user, client->storage->name);
			if (cache->uidnext <= uid && cache->uidvalidity != 0)
				cache->uidnext = uid+1;

			if (cache->next_action_timestamp == (time_t)-1) {
				cache->next_action_timestamp = ioloop_time +
					weighted_rand(client->user->profile->mail_action_delay);
			}
		}
	}
}

int client_profile_handle_untagged(struct client *client,
				   const struct imap_arg *args)
{
	if (client_handle_untagged(client, args) < 0)
		return -1;

	if (client->login_state != LSTATE_SELECTED)
		return 0;

	if (imap_arg_atom_equals(&args[1], "EXISTS"))
		client_profile_handle_exists(client);
	if (imap_arg_atom_equals(&args[1], "FETCH"))
		client_profile_handle_fetch(client, &args[2]);
	return 0;
}

static struct client *user_find_any_client(struct user *user)
{
	struct client *const *clientp, *last_client = NULL;

	/* try to find an idling client */
	array_foreach(&user->clients, clientp) {
		last_client = *clientp;
		if ((*clientp)->idling)
			return *clientp;
	}
	i_assert(last_client != NULL);
	return last_client;
}

static unsigned int
user_get_timeout_interval(struct user *user, enum user_timestamp ts)
{
	switch (ts) {
	case USER_TIMESTAMP_INBOX_DELIVERY:
		return user->profile->mail_inbox_delivery_interval;
	case USER_TIMESTAMP_SPAM_DELIVERY:
		return user->profile->mail_spam_delivery_interval;
	case USER_TIMESTAMP_WRITE_MAIL:
		return user->profile->mail_send_interval;
	case USER_TIMESTAMP_COUNT:
		break;
	}
	i_unreached();
}

static time_t user_get_next_timeout(struct user *user, enum user_timestamp ts)
{
	unsigned int interval = user_get_timeout_interval(user, ts);

	if (interval == 0)
		return 2147483647; /* TIME_T_MAX - lets assume this is far enough.. */
	return ioloop_time + weighted_rand(interval);
}

static void
user_mailbox_action(struct user *user, struct user_mailbox_cache *cache)
{
	struct client *client;
	const char *cmd;

	client = user_find_client_by_mailbox(user, cache->mailbox_name);
	if (client == NULL)
		return;

	/* fetch new messages' bodies (although perhaps we should do
	   this one at a time with some delay?) */
	cache = user_get_mailbox_cache(client->user, client->storage->name);
	cmd = t_strdup_printf("UID FETCH %u:%u (%s)", cache->last_action_uid,
			      cache->uidnext, client->profile->imap_fetch_manual);
	cache->last_action_uid = cache->uidnext;
	client->state = STATE_FETCH2;
	command_send(client, cmd, state_callback);
}

static void deliver_new_mail(struct user *user, const char *mailbox)
{
	const char *rcpt_to = strcmp(mailbox, "INBOX") == 0 ? user->username :
		t_strdup_printf("%s+%s", user->username, mailbox);

	imaptest_lmtp_send(user->profile->profile->lmtp_port,
			   rcpt_to, mailbox_source);
}

static void user_timeout(struct user *user)
{
	struct user_mailbox_cache *const *mailboxp;
	enum user_timestamp ts;
	struct client *client;
	struct command *cmd;

	for (ts = 0; ts < USER_TIMESTAMP_COUNT; ts++) {
		if (user->timestamps[ts] > ioloop_time)
			continue;

		switch (ts) {
		case USER_TIMESTAMP_INBOX_DELIVERY:
			deliver_new_mail(user, "INBOX");
			break;
		case USER_TIMESTAMP_SPAM_DELIVERY:
			deliver_new_mail(user, "Spam");
			break;
		case USER_TIMESTAMP_WRITE_MAIL:
			/* FIXME: write to Drafts first */
			client = user_find_any_client(user);
			if (client != NULL && client->state == STATE_IDLE) {
				client_append_full(client, PROFILE_MAILBOX_SENT,
						   0, "", state_callback, &cmd);
			}
			break;
		case USER_TIMESTAMP_COUNT:
			i_unreached();
		}
		user->timestamps[ts] = user_get_next_timeout(user, ts);
	}
	array_foreach(&user->mailboxes, mailboxp) {
		if ((*mailboxp)->next_action_timestamp <= ioloop_time &&
		    (*mailboxp)->next_action_timestamp != (time_t)-1) {
			user_mailbox_action(user, *mailboxp);
			(*mailboxp)->next_action_timestamp = (time_t)-1;
		}
	}
	user_set_timeout(user);
}

static void user_fill_timestamps(struct user *user)
{
	enum user_timestamp ts;

	for (ts = 0; ts < USER_TIMESTAMP_COUNT; ts++)
		user->timestamps[ts] = user_get_next_timeout(user, ts);
}

static void user_set_timeout(struct user *user)
{
	struct user_mailbox_cache *const *mailboxp;
	time_t lowest_timestamp;
	unsigned int i;

	lowest_timestamp = user->timestamps[0];
	for (i = 1; i < N_ELEMENTS(user->timestamps); i++) {
		if (lowest_timestamp > user->timestamps[i])
			lowest_timestamp = user->timestamps[i];
	}
	array_foreach(&user->mailboxes, mailboxp) {
		if ((*mailboxp)->next_action_timestamp != (time_t)-1 &&
		    lowest_timestamp > (*mailboxp)->next_action_timestamp)
			lowest_timestamp = (*mailboxp)->next_action_timestamp;
	}

	if (user->to != NULL)
		timeout_remove(&user->to);
	if (lowest_timestamp <= ioloop_time)
		user->to = timeout_add_short(0, user_timeout, user);
	else {
		user->to = timeout_add((lowest_timestamp - ioloop_time) * 1000,
				       user_timeout, user);
	}
}

void profile_start_user(struct user *user)
{
	user_set_timeout(user);
}

void profile_stop_user(struct user *user)
{
	if (user->to != NULL)
		timeout_remove(&user->to);
}

static void
user_init_client_profiles(struct user *user, struct profile *profile)
{
	struct profile_client *const *clientp;

	p_array_init(&user->client_profiles, user->pool,
		     array_count(&profile->clients));
	while (array_count(&user->client_profiles) == 0) {
		array_foreach(&profile->clients, clientp) {
			if ((unsigned int)rand() % 100 < (*clientp)->percentage)
				array_append(&user->client_profiles, clientp, 1);
		}
	}
}

static void
users_add_from_user_profile(const struct profile_user *user_profile,
			    struct profile *profile, ARRAY_TYPE(user) *users)
{
	struct user *user;
	string_t *str = t_str_new(64);
	unsigned int i, prefix_len;

	str_append(str, user_profile->username_prefix);
	prefix_len = str_len(str);

	for (i = 1; i <= user_profile->user_count; i++) {
		str_truncate(str, prefix_len);
		str_printfa(str, "%u", i);
		user = user_get(str_c(str));
		user->profile = user_profile;
		user_init_client_profiles(user, profile);
		user_fill_timestamps(user);
		array_append(users, &user, 1);
	}
}

void profile_add_users(struct profile *profile, ARRAY_TYPE(user) *users)
{
	struct profile_user *const *userp;

	i_array_init(users, 128);
	array_foreach(&profile->users, userp)
		users_add_from_user_profile(*userp, profile, users);
}
