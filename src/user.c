/* Copyright (c) 2013-2018 ImapTest authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "hash.h"
#include "ioloop.h"
#include "str.h"
#include "time-util.h"
#include "settings.h"
#include "profile.h"
#include "imap-client.h"
#include "mailbox.h"
#include "mailbox-source.h"
#include "user.h"
#include "var-expand.h"

#include <stdlib.h>

static HASH_TABLE(const char *, struct user *) users_hash;
static ARRAY_TYPE(user) users = ARRAY_INIT;
static struct profile *users_profile;

static inline const char *
t_nagfree_strdup_printf(char const* format, ...)
{
	va_list args;
	const char *ret;

	/* Different compilers need different ways to be explicitly told to
	   ignore this following usage of a non-literal format string. */
#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wformat-nonliteral"
#elif defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
#endif
	va_start(args, format);
	ret = t_strdup_vprintf(format, args);
#if defined(__clang__)
#pragma clang diagnostic pop
#elif defined(__GNUC__)
#pragma GCC diagnostic pop
#endif
	va_end(args);

	return ret;
}

struct user *user_get(const char *username, struct mailbox_source *source)
{
	struct user *user;
	pool_t pool;

	user = hash_table_lookup(users_hash, username);
	if (user != NULL)
		return user;

	pool = pool_alloconly_create("user", 1024*2);
	user = p_new(pool, struct user, 1);
	user->pool = pool;
	user->username = p_strdup(pool, username);
	user->password = conf.password;
	user->mailbox_source = source;
	mailbox_source_ref(user->mailbox_source);
	user->next_min_timestamp = INT_MAX;
	p_array_init(&user->clients, user->pool, 2);
	hash_table_insert(users_hash, user->username, user);
	return user;
}

static struct user *user_get_random_from_conf(struct mailbox_source *source)
{
	static int prev_user = 0, prev_domain = 0;
	const char *const *userp, *p, *username;
	struct user *user;
	unsigned int i;

	if (array_is_created(&conf.usernames)) {
		i = i_rand_limit(array_count(&conf.usernames));
		userp = array_idx(&conf.usernames, i);
		p = strchr(*userp, ':');
		if (p == NULL) {
			user = user_get(*userp, source);
		} else {
			user = user_get(t_strdup_until(*userp, p), source);
			if (strncmp(p + 1, "{PLAIN}", 7) == 0)
				p += 7;
			user->password = p_strdup(user->pool, p+1);
		}
	} else {
		prev_user = random() % conf.users_rand_count + conf.users_rand_start;
		prev_domain = random() % conf.domains_rand_count + conf.domains_rand_start;
		username = t_nagfree_strdup_printf(conf.username_template,
						   prev_user, prev_domain);
		user = user_get(username, source);
	}
	i_assert(*user->username != '\0');
	return user;
}

#define USER_CLIENT_CAN_CONNECT(uc) \
	((uc->last_logout <= 0 ? \
	 (ioloop_time >= uc->user->timestamps[USER_TIMESTAMP_LOGIN]) : \
	 (ioloop_time - uc->last_logout >= (time_t)uc->profile->login_interval)) && \
	array_count(&uc->clients) < uc->profile->connection_max_count)


static bool user_can_connect_clients(struct user *user)
{
	struct user_client *const *clients;
	unsigned int i, count;
	bool ret = FALSE;

	clients = array_get(&user->clients, &count);
	for (i = 0; i < count; i++) {
		if (USER_CLIENT_CAN_CONNECT(clients[i]))
			ret = TRUE;
	}
	return ret;
}

bool user_get_random(struct mailbox_source *source, struct user **user_r)
{
	struct user *const *u;
	unsigned int start_idx, i, count;

	if (users_profile == NULL) {
		*user_r = user_get_random_from_conf(source);
		return TRUE;
	}

	u = array_get(&users, &count);
	start_idx = i_rand_limit(count);
	for (i = 0; i < count; i++) {
		unsigned int idx = (i + start_idx) % count;
		if (user_can_connect_clients(u[idx])) {
			*user_r = u[idx];
			return TRUE;
		}
	}
	return FALSE;
}

static void user_free(struct user *user)
{
	mailbox_source_unref(&user->mailbox_source);
	pool_unref(&user->pool);
}

void user_add_client(struct user *user, struct client *client)
{
	if (client->user_client == NULL)
		return;

	array_append(&client->user_client->clients, &client, 1);
	if (user->active_client == NULL)
		user->active_client = client->user_client;
}

static void user_update_active_client(struct user *user)
{
	struct user_client *const *clients, *uc;
	unsigned int i, j, count;

	clients = array_get(&user->clients, &count);
	j = i_rand_limit(count);
	for (i = 0; i < count; i++) {
		uc = clients[(i+j)%count];
		if (array_count(&uc->clients) > 0) {
			user->active_client = uc;
			return;
		}
	}
	user->active_client = NULL;
	return;
}

void user_remove_client(struct user *user, struct client *client)
{
	struct client *const *clients;
	unsigned int i, count;

	if (client->user_client == NULL)
		return;

	clients = array_get(&client->user_client->clients, &count);
	for (i = 0; i < count; i++) {
		if (clients[i] == client) {
			array_delete(&client->user_client->clients, i, 1);
			if (count == 1 && user->active_client == client->user_client)
				user_update_active_client(user);
			return;
		}
	}
	i_unreached();
}

bool user_get_new_client_profile(struct user *user,
				 struct user_client **user_client_r)
{
	struct user_client *const *user_clients, *lowest_uc = NULL;
	unsigned int i, uc_count, lowest_count = UINT_MAX;

	*user_client_r = NULL;
	if (user->profile == NULL)
		return TRUE;

	/* find the user_client with the lowest connection count.
	   we also must be able to connect to it. */
	user_clients = array_get(&user->clients, &uc_count);
	for (i = 0; i < uc_count; i++) {
		if (USER_CLIENT_CAN_CONNECT(user_clients[i]) &&
		    lowest_count > array_count(&user_clients[i]->clients)) {
			lowest_count = array_count(&user_clients[i]->clients);
			lowest_uc = user_clients[i];
		}
	}
	if (lowest_uc == NULL)
		return FALSE;
	*user_client_r = lowest_uc;
	return TRUE;
}

time_t user_get_next_login_time(struct user *user)
{
	struct user_client *const *user_clients;
	unsigned int i, uc_count;
	time_t next_login, lowest_next_login_time = INT_MAX;

	if (user->profile == NULL)
		return ioloop_time;

	user_clients = array_get(&user->clients, &uc_count);
	for (i = 0; i < uc_count; i++) {
		if (user_clients[i]->last_logout <= 0)
			continue;
		next_login = user_clients[i]->last_logout +
			user_clients[i]->profile->login_interval;
		if (lowest_next_login_time > next_login)
			lowest_next_login_time = next_login;
	}
	if (lowest_next_login_time == INT_MAX) {
		/* first login for user */
		return user->timestamps[USER_TIMESTAMP_LOGIN];
	}
	return lowest_next_login_time;
}

struct imap_client *
user_find_client_by_mailbox(struct user_client *uc, const char *mailbox)
{
	struct client *_client;

	array_foreach_elem(&uc->clients, _client) {
		struct imap_client *client = imap_client(_client);
		if (client != NULL &&
		    client->client.login_state != LSTATE_NONAUTH &&
		    strcmp(client->storage->name, mailbox) == 0)
			return client;
	}
	return NULL;
}

const char *user_get_new_mailbox(struct client *client)
{
	struct user_client *uc = client->user_client;

	if (uc == NULL) {
		struct var_expand_table exp_table[] = {
			{ 'i', dec2str(client->idx), NULL },
			{ '\0', NULL, NULL }
		};
		const char *error;
		string_t *str = t_str_new(32);
		if (var_expand(str, conf.mailbox, exp_table, &error) != 1) {
			i_fatal("Mailbox format invalid: %s", error);
		}
		return str_c(str);
	}

	if (user_find_client_by_mailbox(uc, "INBOX") == NULL)
		return "INBOX";
	if (user_find_client_by_mailbox(uc, PROFILE_MAILBOX_SENT) == NULL)
		return PROFILE_MAILBOX_SENT;
	if (user_find_client_by_mailbox(uc, PROFILE_MAILBOX_DRAFTS) == NULL)
		return PROFILE_MAILBOX_DRAFTS;
	return "INBOX";
}

struct user_mailbox_cache *
user_get_mailbox_cache(struct user_client *uc, const char *name)
{
	struct user_mailbox_cache *mailbox;

	array_foreach_elem(&uc->mailboxes, mailbox) {
		if (strcmp(mailbox->mailbox_name, name) == 0)
			return mailbox;
	}
	mailbox = p_new(uc->user->pool, struct user_mailbox_cache, 1);
	mailbox->mailbox_name = p_strdup(uc->user->pool, name);
	mailbox->next_action_timestamp = (time_t)-1;
	array_append(&uc->mailboxes, &mailbox, 1);
	return mailbox;
}

static int users_min_timestamp_cmp(struct user *const *u1,
				   struct user *const *u2)
{
	return (*u1)->next_min_timestamp - (*u2)->next_min_timestamp;
}

const ARRAY_TYPE(user) *users_get_sort_by_min_timestamp(void)
{
	array_sort(&users, users_min_timestamp_cmp);
	return &users;
}

void users_free_all(void)
{
	const char *username;
	struct user *user;
	struct hash_iterate_context *iter;

	iter = hash_table_iterate_init(users_hash);
	while (hash_table_iterate(iter, users_hash, &username, &user))
		user_free(user);
	hash_table_iterate_deinit(&iter);

	hash_table_clear(users_hash, FALSE);
	if (array_is_created(&users))
		array_clear(&users);
}

void users_init(struct profile *profile, struct mailbox_source *source)
{
	hash_table_create(&users_hash, default_pool, 0, str_hash, strcmp);
	users_profile = profile;

	if (profile != NULL)
		profile_add_users(profile, &users, source);
}

void users_deinit(void)
{
	users_free_all();

	hash_table_destroy(&users_hash);
	if (array_is_created(&users))
		array_free(&users);
}
