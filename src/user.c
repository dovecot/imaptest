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

	pool = pool_alloconly_create("user", 512+256);
	user = p_new(pool, struct user, 1);
	user->pool = pool;
	user->username = p_strdup(pool, username);
	user->password = conf.password;
	p_array_init(&user->clients, user->pool, 2);
	p_array_init(&user->mailboxes, user->pool, 2);
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
	if (array_count(&user->clients) == 0 && user->profile != NULL)
		profile_start_user(user);
	array_append(&user->clients, &client, 1);
}

void user_remove_client(struct user *user, struct client *client)
{
	struct client *const *clients;
	unsigned int i, count;

	clients = array_get(&user->clients, &count);
	for (i = 0; i < count; i++) {
		if (clients[i] == client) {
			array_delete(&user->clients, i, 1);
			if (count == 1)
				profile_stop_user(user);
			return;
		}
	}
	i_unreached();
}

struct profile_client *user_get_new_client_profile(struct user *user)
{
	struct profile_client *const *profiles, *lowest_profile = NULL;
	unsigned int profile_count, lowest_count = UINT_MAX;
	struct client *const *clientp;
	unsigned int i, *counts;

	if (user->profile == NULL)
		return NULL;

	/* count how many clients we already have for different profiles */
	profiles = array_get(&user->client_profiles, &profile_count);
	i_assert(profile_count > 0);
	counts = t_new(unsigned int, profile_count);

	array_foreach(&user->clients, clientp) {
		for (i = 0; i < profile_count; i++) {
			if ((*clientp)->profile == profiles[i]) {
				counts[i]++;
				break;
			}
		}
		i_assert(i < profile_count);
	}
	/* find the profile with the lowest count */
	for (i = 0; i < profile_count; i++) {
		if (lowest_count > counts[i]) {
			lowest_count = counts[i];
			lowest_profile = profiles[i];
		}
	}
	i_assert(lowest_profile != NULL);
	return lowest_profile;
}

struct client *
user_find_client_by_mailbox(struct user *user, const char *mailbox)
{
	struct client *const *clientp;

	array_foreach(&user->clients, clientp) {
		if (strcmp((*clientp)->storage->name, mailbox) == 0)
			return *clientp;
	}
	return NULL;
}

const char *user_get_new_mailbox(struct user *user, struct client *client)
{
	if (user->profile == NULL)
		return t_strdup_printf(conf.mailbox, client->idx);

	if (user_find_client_by_mailbox(user, "INBOX") == NULL)
		return "INBOX";
	if (user_find_client_by_mailbox(user, PROFILE_MAILBOX_SENT) == NULL)
		return PROFILE_MAILBOX_SENT;
	if (user_find_client_by_mailbox(user, PROFILE_MAILBOX_DRAFTS) == NULL)
		return PROFILE_MAILBOX_DRAFTS;
	return "INBOX";
}

struct user_mailbox_cache *
user_get_mailbox_cache(struct user *user, const char *name)
{
	struct user_mailbox_cache *const *mailboxp, *mailbox;

	array_foreach(&user->mailboxes, mailboxp) {
		if (strcmp((*mailboxp)->mailbox_name, name) == 0)
			return *mailboxp;
	}
	mailbox = p_new(user->pool, struct user_mailbox_cache, 1);
	mailbox->mailbox_name = p_strdup(user->pool, name);
	mailbox->next_action_timestamp = (time_t)-1;
	array_append(&user->mailboxes, &mailbox, 1);
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
