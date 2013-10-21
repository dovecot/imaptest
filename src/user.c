/* Copyright (c) 2013 Timo Sirainen */

#include "lib.h"
#include "array.h"
#include "hash.h"
#include "str.h"
#include "settings.h"
#include "profile.h"
#include "client.h"
#include "mailbox.h"
#include "user.h"

#include <stdlib.h>

static HASH_TABLE(const char *, struct user *) users_hash;
static ARRAY_TYPE(user) users = ARRAY_INIT;
static struct profile *users_profile;

struct user *user_get(const char *username)
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
	p_array_init(&user->clients, user->pool, 2);
	hash_table_insert(users_hash, user->username, user);
	return user;
}

static struct user *user_get_random_from_conf(void)
{
	static int prev_user = 0, prev_domain = 0;
	const char *const *userp, *p, *username;
	struct user *user;
	unsigned int i;

	if (array_is_created(&conf.usernames)) {
		i = rand() % array_count(&conf.usernames);
		userp = array_idx(&conf.usernames, i);
		p = strchr(*userp, ':');
		if (p == NULL) {
			user = user_get(*userp);
		} else {
			user = user_get(t_strdup_until(*userp, p));
			user->password = p_strdup(user->pool, p+1);
		}
	} else {
		if (rand() % 2 == 0 && prev_user != 0) {
			/* continue with same user */
		} else {
			prev_user = random() % USER_RAND + 1;
			prev_domain = random() % DOMAIN_RAND + 1;
		}
		username = t_strdup_printf(conf.username_template,
					   prev_user, prev_domain);
		user = user_get(username);
	}
	i_assert(*user->username != '\0');
	return user;
}

struct user *user_get_random(void)
{
	struct user *const *userp;
	unsigned int idx;

	if (users_profile == NULL)
		return user_get_random_from_conf();

	idx = rand() % array_count(&users);
	userp = array_idx(&users, idx);
	return *userp;
}

void user_add_client(struct user *user, struct client *client)
{
	if (client->user_client == NULL)
		return;

	array_append(&client->user_client->clients, &client, 1);
	if (user->active_client == NULL) {
		user->active_client = client->user_client;
		profile_start_user(user);
	}
}

static void user_update_active_client(struct user *user)
{
	struct user_client *const *clients, *uc;
	unsigned int i, j, count;

	clients = array_get(&user->clients, &count);
	j = rand() % count;
	for (i = 0; i < count; i++) {
		uc = clients[(i+j)%count];
		if (array_count(&uc->clients) > 0) {
			user->active_client = uc;
			return;
		}
	}
	user->active_client = NULL;
	profile_stop_user(user);
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

struct user_client *user_get_new_client_profile(struct user *user)
{
	struct user_client *const *user_clients, *lowest_uc = NULL;
	unsigned int i, uc_count, lowest_count = UINT_MAX;

	if (user->profile == NULL)
		return NULL;

	/* find the user_client with the lowest connection count */
	user_clients = array_get(&user->clients, &uc_count);
	for (i = 0; i < uc_count; i++) {
		if (lowest_count > array_count(&user_clients[i]->clients)) {
			lowest_count = array_count(&user_clients[i]->clients);
			lowest_uc = user_clients[i];
		}
	}
	i_assert(lowest_uc != NULL);
	return lowest_uc;
}

struct client *
user_find_client_by_mailbox(struct user_client *uc, const char *mailbox)
{
	struct client *const *clientp;

	array_foreach(&uc->clients, clientp) {
		if ((*clientp)->login_state != LSTATE_NONAUTH &&
		    strcmp((*clientp)->storage->name, mailbox) == 0)
			return *clientp;
	}
	return NULL;
}

const char *user_get_new_mailbox(struct client *client)
{
	struct user_client *uc = client->user_client;

	if (uc == NULL)
		return t_strdup_printf(conf.mailbox, client->idx);

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
	struct user_mailbox_cache *const *mailboxp, *mailbox;

	array_foreach(&uc->mailboxes, mailboxp) {
		if (strcmp((*mailboxp)->mailbox_name, name) == 0)
			return *mailboxp;
	}
	mailbox = p_new(uc->user->pool, struct user_mailbox_cache, 1);
	mailbox->mailbox_name = p_strdup(uc->user->pool, name);
	mailbox->next_action_timestamp = (time_t)-1;
	array_append(&uc->mailboxes, &mailbox, 1);
	return mailbox;
}

void users_init(struct profile *profile)
{
	hash_table_create(&users_hash, default_pool, 0, str_hash, strcmp);
	users_profile = profile;

	if (profile != NULL)
		profile_add_users(profile, &users);
}

void users_deinit(void)
{
	const char *username;
	struct user *user;
	struct hash_iterate_context *iter;

	iter = hash_table_iterate_init(users_hash);
	while (hash_table_iterate(iter, users_hash, &username, &user))
		pool_unref(&user->pool);
	hash_table_iterate_deinit(&iter);

	hash_table_destroy(&users_hash);
	if (array_is_created(&users))
		array_free(&users);
}
