/* Copyright (c) 2013-2018 ImapTest authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "str.h"
#include "var-expand.h"
#include "smtp-address.h"
#include "imap-arg.h"
#include "imap-quote.h"
#include "imap-client.h"
#include "mailbox.h"
#include "mailbox-source.h"
#include "commands.h"
#include "imaptest-lmtp.h"
#include "profile.h"

#include <stdlib.h>
#include <math.h>

#define RANDU (i_rand_limit(RAND_MAX) / (double)RAND_MAX)
#define RANDN2(mu, sigma) \
	(mu + (i_rand()%2 != 0 ? -1.0 : 1.0) * sigma * pow(-log(0.99999*RANDU), 0.5))
#define weighted_rand(n) \
	(int)RANDN2(n, n/2)

static time_t users_min_timestamp = INT_MAX;
static struct timeout *to_users;

static void user_mailbox_action_move(struct imap_client *client,
				     const char *mailbox, uint32_t uid);
static void user_set_min_timestamp(struct user *user, time_t min_timestamp);
static void users_timeout_update(void);

static void client_profile_init_mailbox(struct imap_client *client)
{
	struct user_mailbox_cache *cache;

	cache = user_get_mailbox_cache(client->client.user_client,
				       client->storage->name);
	if (cache->uidvalidity != 0)
		return;

	cache->uidvalidity = client->storage->uidvalidity;
	cache->uidnext = client->view->select_uidnext;
	cache->highest_modseq = client->view->highest_modseq;

	cache->last_action_uid = cache->uidnext;
}

static void
client_profile_send_missing_creates(struct imap_client *client)
{
	if ((client->client.user->profile->mail_inbox_move_filter_percentage > 0 ||
	     client->client.user->profile->mail_spam_delivery_interval > 0) &&
	    imap_client_mailboxes_list_find(client, PROFILE_MAILBOX_SPAM) == NULL)
		command_send(client, "CREATE \""PROFILE_MAILBOX_SPAM"\"", state_callback);

	if (client->client.user->profile->mail_inbox_reply_percentage > 0 ||
	    client->client.user->profile->mail_send_interval > 0) {
		if (imap_client_mailboxes_list_find(client, PROFILE_MAILBOX_DRAFTS) == NULL)
			command_send(client, "CREATE \""PROFILE_MAILBOX_DRAFTS"\"", state_callback);
		if (imap_client_mailboxes_list_find(client, PROFILE_MAILBOX_SENT) == NULL)
			command_send(client, "CREATE \""PROFILE_MAILBOX_SENT"\"", state_callback);
	}
}

int imap_client_profile_send_more_commands(struct client *_client)
{
	struct imap_client *client = (struct imap_client *)_client;
	string_t *cmd = t_str_new(128);

	if (array_count(&client->commands) > 0)
		return 0;

	switch (_client->login_state) {
	case LSTATE_NONAUTH:
		str_append(cmd, "LOGIN ");
		imap_append_astring(cmd, _client->user->username);
		str_append_c(cmd, ' ');
		imap_append_astring(cmd, _client->user->password);
		client->client.state = STATE_LOGIN;
		break;
	case LSTATE_AUTH:
		if (!array_is_created(&client->mailboxes_list)) {
			str_append(cmd, "LIST \"\" *");
			client->client.state = STATE_LIST;
			imap_client_mailboxes_list_begin(client);
		} else {
			client_profile_send_missing_creates(client);
			str_append(cmd, "SELECT ");
			imap_append_astring(cmd, client->storage->name);
			client->client.state = STATE_SELECT;
		}
		break;
	case LSTATE_SELECTED:
		client_profile_init_mailbox(client);
		str_append(cmd, "IDLE");
		client->idle_wait_cont = TRUE;
		client->client.state = STATE_IDLE;
		break;
	}
	command_send(client, str_c(cmd), state_callback);
	if (client->client.state == STATE_IDLE) {
		/* set this after sending the command */
		client->client.idling = TRUE;
	}
	return 0;
}

static void client_profile_handle_exists(struct imap_client *client)
{
	struct user_mailbox_cache *cache;
	const char *cmd;

	/* fetch new messages */
	cache = user_get_mailbox_cache(client->client.user_client, client->storage->name);
	cmd = t_strdup_printf("UID FETCH %u:* (%s)", cache->uidnext,
			      client->client.user_client->profile->imap_fetch_immediate);
	client->client.state = STATE_FETCH;
	command_send(client, cmd, state_callback);
}

static void client_profile_handle_fetch(struct imap_client *client,
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

			cache = user_get_mailbox_cache(client->client.user_client,
						       client->storage->name);
			if (cache->uidnext <= uid && cache->uidvalidity != 0)
				cache->uidnext = uid+1;

			if ((unsigned)i_rand() % 100 < client->client.user->profile->mail_inbox_move_filter_percentage)
				user_mailbox_action_move(client, PROFILE_MAILBOX_SPAM, uid);
			else if (cache->next_action_timestamp == (time_t)-1) {
				cache->next_action_timestamp = ioloop_time +
					weighted_rand(client->client.user->profile->mail_action_delay);
				user_set_min_timestamp(client->client.user, cache->next_action_timestamp);
			}
		}
	}
}

int imap_client_profile_handle_untagged(struct imap_client *client,
					const struct imap_arg *args)
{
	if (imap_client_handle_untagged(client, args) < 0)
		return -1;

	if (client->client.login_state != LSTATE_SELECTED)
		return 0;

	if (imap_arg_atom_equals(&args[1], "EXISTS"))
		client_profile_handle_exists(client);
	if (imap_arg_atom_equals(&args[1], "FETCH"))
		client_profile_handle_fetch(client, &args[2]);
	return 0;
}

static struct imap_client *user_find_any_imap_client(struct user_client *uc)
{
	struct client *const *clientp;
	struct imap_client *last_client = NULL;

	/* try to find an idling client */
	array_foreach(&uc->clients, clientp) {
		struct imap_client *last_client = imap_client(*clientp);
		if (last_client != NULL && last_client->client.idling)
			return last_client;
	}
	i_assert(last_client != NULL);
	return last_client;
}

static unsigned int
user_get_timeout_interval(struct user *user, enum user_timestamp ts)
{
	switch (ts) {
	case USER_TIMESTAMP_LOGIN:
		return 0;
	case USER_TIMESTAMP_INBOX_DELIVERY:
		return user->profile->mail_inbox_delivery_interval;
	case USER_TIMESTAMP_SPAM_DELIVERY:
		return user->profile->mail_spam_delivery_interval;
	case USER_TIMESTAMP_WRITE_MAIL:
		return user->profile->mail_send_interval;
	case USER_TIMESTAMP_LOGOUT:
		return user->profile->mail_session_length;
	case USER_TIMESTAMP_COUNT:
		break;
	}
	i_unreached();
}

static time_t
user_get_next_timeout(struct user *user, time_t start_time,
		      enum user_timestamp ts)
{
	unsigned int interval = user_get_timeout_interval(user, ts);

	if (interval == 0)
		return (time_t)-1;
	return start_time + weighted_rand(interval);
}

static void user_mailbox_action_delete(struct imap_client *client, uint32_t uid)
{
	const char *cmd;

	/* FIXME: support also deletion via Trash */
	cmd = t_strdup_printf("UID STORE %u +FLAGS \\Deleted", uid);
	client->client.state = STATE_STORE_DEL;
	command_send(client, cmd, state_callback);

	if ((client->capabilities & CAP_UIDPLUS) != 0)
		cmd = t_strdup_printf("UID EXPUNGE %u", uid);
	else
		cmd = "EXPUNGE";
	client->client.state = STATE_EXPUNGE;
	command_send(client, cmd, state_callback);
}

static void user_mailbox_action_move(struct imap_client *client,
				     const char *mailbox, uint32_t uid)
{
	string_t *cmd = t_str_new(128);

	/* FIXME: should use MOVE if client supports it */
	str_printfa(cmd, "UID COPY %u ", uid);
	imap_append_astring(cmd, mailbox);
	client->client.state = STATE_COPY;
	command_send(client, str_c(cmd), state_callback);

	user_mailbox_action_delete(client, uid);
}

static void user_draft_callback(struct imap_client *client, struct command *cmd,
				const struct imap_arg *args,
				enum command_reply reply)
{
	const char *uidvalidity, *uidstr;
	uint32_t uid;
	time_t ts;

	i_assert(cmd == client->client.user_client->draft_cmd);
	client->client.user_client->draft_cmd = NULL;

	if (reply != REPLY_OK) {
		state_callback(client, cmd, args, reply);
		return;
	}

	if (!imap_arg_atom_equals(&args[1], "[APPENDUID"))
		i_fatal("FIXME: currently we require server to support UIDPLUS");
	if (!imap_arg_get_atom(&args[2], &uidvalidity) ||
	    !imap_arg_get_atom(&args[3], &uidstr) ||
	    str_to_uint32(t_strcut(uidstr, ']'), &uid) < 0 || uid == 0) {
		imap_client_input_error(client, "Server replied invalid line to APPEND");
		return;
	}
	i_assert(client->client.user_client->draft_uid == 0);
	client->client.user_client->draft_uid = uid;

	ts = ioloop_time + weighted_rand(client->client.user->profile->mail_write_duration);
	client->client.user->timestamps[USER_TIMESTAMP_WRITE_MAIL] = ts;
	user_set_min_timestamp(client->client.user, ts);
}

static bool user_write_mail(struct user_client *uc)
{
	struct imap_client *client, *client2;
	struct command *cmd;

	i_assert(uc->draft_cmd == NULL);

	client = user_find_client_by_mailbox(uc, PROFILE_MAILBOX_DRAFTS);
	if (client == NULL)
		return TRUE;

	if (uc->draft_uid == 0) {
		/* start writing the mail as a draft */
		if (client->client.state != STATE_IDLE)
			return TRUE;

		/* disable WRITE_MAIL timeout until writing is finished */
		uc->user->timestamps[USER_TIMESTAMP_WRITE_MAIL] = (time_t)-1;
		imap_client_append_full(client, PROFILE_MAILBOX_DRAFTS,
					"\\Draft", "",
					user_draft_callback, &uc->draft_cmd);
		return FALSE;
	} else {
		/* save mail to Sent and delete draft */
		client2 = user_find_any_imap_client(uc);
		if (client2 != NULL && client2->client.state == STATE_IDLE) {
			imap_client_append_full(client2, PROFILE_MAILBOX_SENT,
						NULL, "", state_callback, &cmd);
		}
		user_mailbox_action_delete(client, uc->draft_uid);
		uc->draft_uid = 0;
		return TRUE;
	}
}

static void user_mailbox_action_reply(struct imap_client *client, uint32_t uid)
{
	const char *cmd;

	if (client->client.user_client->draft_cmd != NULL ||
	    client->client.user_client->draft_cmd != 0)
		return;

	/* we'll do this the easy way, although it doesn't exactly emulate the
	   user+client: start up a regular mail write and immediately mark the
	   current message as \Answered */
	user_write_mail(client->client.user_client);

	cmd = t_strdup_printf("UID STORE %u +FLAGS \\Answered", uid);
	client->client.state = STATE_STORE;
	command_send(client, cmd, state_callback);
}

static void user_mailbox_action_search(struct imap_client *client) {
	const char *cmd;

        cmd = t_strdup_printf(
            "SEARCH %s",
            client->client.user_client->profile->imap_search_query);
        client->client.state = STATE_SEARCH;
	command_send(client, cmd, state_callback);
}

static bool
user_mailbox_action(struct user *user, struct user_mailbox_cache *cache)
{
  struct user_client *uc = user->active_client;
  struct imap_client *client;
  const char *cmd;
  uint32_t uid = cache->last_action_uid;

  client = user_find_client_by_mailbox(uc, cache->mailbox_name);
  if (client == NULL)
    return FALSE;

  if (uid >= cache->uidnext)
    return FALSE;

  if (!cache->last_action_uid_body_fetched) {
    /* fetch the next new message's body */
    cache = user_get_mailbox_cache(uc, client->storage->name);
    cmd = t_strdup_printf("UID FETCH %u (%s)", uid, client->client.user_client->profile->imap_fetch_manual);

    client->client.state = STATE_FETCH2;
    command_send(client, cmd, state_callback);

    /* and mark the message as \Seen */
    cmd = t_strdup_printf("UID STORE %u +FLAGS \\Seen", uid);
    client->client.state = STATE_STORE;
    command_send(client, cmd, state_callback);

    if (client->client.user_client->profile->imap_metadata_extension != NULL && client->view->last_xguid != NULL) {
      // i_debug("fetching metadata with %d, %s", client->view->last_uid, client->view->last_xguid);
      cmd = t_strdup_printf("GETMETADATA INBOX (%s%s)", client->client.user_client->profile->imap_metadata_extension,
                            client->view->last_xguid);
      client->client.state = STATE_GET_METADATA;
      command_send(client, cmd, state_callback);
    }
    if (client->view->last_xguid != NULL) {
    // free the xguid buffer!
      free(client->view->last_xguid);
    }
    cache->last_action_uid_body_fetched = TRUE;
    return TRUE;
	}
	/* handle the action for mails in INBOX */
  cache->last_action_uid++;
  cache->last_action_uid_body_fetched = FALSE;

  if (strcasecmp(cache->mailbox_name, "INBOX") != 0)
    return TRUE;

  if ((unsigned) i_rand() % 100 < user->profile->mail_inbox_delete_percentage) {
          user_mailbox_action_delete(client, uid);
  } else if ((unsigned) i_rand() % 100 < user->profile->mail_inbox_move_percentage) {
          user_mailbox_action_move(client, PROFILE_MAILBOX_SPAM, uid);
  }
	else if ((unsigned) i_rand() % 100 < user->profile->mail_inbox_reply_percentage) {
		user_mailbox_action_reply(client, uid);
  }
  else if ((unsigned) i_rand() % 100 < user->profile->mail_inbox_search_percentage) {
          user_mailbox_action_search(client);
  }
  return TRUE;
}

static void deliver_new_mail(struct user *user, const char *mailbox)
{
	struct smtp_address *rcpt_to;
	const char *error;
	if (smtp_address_parse_username(pool_datastack_create(), user->username,
		&rcpt_to, &error) < 0) {
		i_fatal("Username is not a valid e-mail address: %s", error);
	}

	if (strcmp(mailbox, "INBOX") != 0) {
		rcpt_to->localpart =
			t_strdup_printf("%s+%s", rcpt_to->localpart, mailbox);
	}

	imaptest_lmtp_send(user->profile->profile->lmtp_port,
			   user->profile->profile->lmtp_max_parallel_count,
			   rcpt_to, mailbox_source);
}

static bool user_client_is_connected(struct user_client *uc)
{
	struct client *const *clientp;

	if (uc == NULL || array_count(&uc->clients) == 0)
		return FALSE;

	array_foreach(&uc->clients, clientp) {
		if ((*clientp)->state == STATE_LOGOUT)
			return FALSE;
	}
	return TRUE;
}

static void user_set_next_mailbox_action(struct user *user)
{
	struct user_mailbox_cache *const *mailboxp;

	array_foreach(&user->active_client->mailboxes, mailboxp) {
		if ((*mailboxp)->next_action_timestamp <= ioloop_time &&
		    (*mailboxp)->next_action_timestamp != (time_t)-1) {
			(*mailboxp)->next_action_timestamp =
				user_mailbox_action(user, *mailboxp) ?
				(ioloop_time + weighted_rand(user->profile->mail_action_repeat_delay)) :
				(time_t)-1;
		}
		user_set_min_timestamp(user, (*mailboxp)->next_action_timestamp);
	}
}

static void user_logout(struct user_client *uc)
{
	struct client *const *clientp;

	array_foreach(&uc->clients, clientp) {
		if ((*clientp)->login_state == LSTATE_NONAUTH)
			client_disconnect(*clientp);
		else
			client_logout(*clientp);
	}
}

static int user_timestamp_handle(struct user *user, enum user_timestamp ts,
				 bool user_connected)
{
	if (user->timestamps[ts] > ioloop_time)
		return -1;
	if (user->timestamps[ts] == (time_t)-1) {
		if (ts == USER_TIMESTAMP_LOGIN) {
			user->timestamps[ts] = user_get_next_login_time(user);
			user_set_min_timestamp(user, user->timestamps[ts]);
		} else if (ts == USER_TIMESTAMP_LOGOUT && user_connected) {
			/* have to have a logout timestamp when there are
			   connected clients. */
			user->timestamps[ts] =
				user_get_next_timeout(user, ioloop_time, ts);
			i_assert(user->timestamps[ts] > 0);
		}
		return -1;
	}

	switch (ts) {
	case USER_TIMESTAMP_LOGIN:
		if (user_connected)
			return 0;
		client_new_user(user);
		return -1;
	case USER_TIMESTAMP_INBOX_DELIVERY:
		deliver_new_mail(user, "INBOX");
		return 1;
	case USER_TIMESTAMP_SPAM_DELIVERY:
		deliver_new_mail(user, "Spam");
		return 1;
	case USER_TIMESTAMP_WRITE_MAIL:
		if (!user_connected)
			return 0;
		if (user_write_mail(user->active_client))
			return 1;
		/* continue this operation with its own timeout */
		return -1;
	case USER_TIMESTAMP_LOGOUT:
		if (!user_connected)
			return 0;
		user_logout(user->active_client);
		return 1;
	case USER_TIMESTAMP_COUNT:
		break;
	}
	i_unreached();
}

static void user_run_actions(struct user *user)
{
	enum user_timestamp ts;
	bool user_connected = user_client_is_connected(user->active_client);

	if (disconnect_clients) {
		if (user_connected)
			user_logout(user->active_client);
		return;
	}

	user->next_min_timestamp = INT_MAX;
	for (ts = 0; ts < USER_TIMESTAMP_COUNT; ts++) {
		switch (user_timestamp_handle(user, ts, user_connected)) {
		case -1:
			break;
		case 0:
			user->timestamps[ts] = (time_t)-1;
			break;
		case 1:
			user->timestamps[ts] =
				user_get_next_timeout(user, ioloop_time, ts);
			break;
		}
		user_set_min_timestamp(user, user->timestamps[ts]);
	}
	if (user->active_client != NULL && user_connected)
		user_set_next_mailbox_action(user);
}

static void user_fill_timestamps(struct user *user, time_t start_time)
{
	enum user_timestamp ts;
	unsigned int interval;

	for (ts = 0; ts < USER_TIMESTAMP_COUNT; ts++) {
		interval = user_get_timeout_interval(user, ts);
		user->timestamps[ts] = interval == 0 ? (time_t)-1 :
			(time_t)(start_time + i_rand() % interval);
		user_set_min_timestamp(user, user->timestamps[ts]);
	}
	user->timestamps[USER_TIMESTAMP_LOGIN] = start_time;
	user_set_min_timestamp(user, start_time);
}

static void users_timeout(void *context ATTR_UNUSED)
{
	const ARRAY_TYPE(user) *users = users_get_sort_by_min_timestamp();
	struct user *const *userp;

	timeout_remove(&to_users);
	array_foreach(users, userp) {
		if (ioloop_time < (*userp)->next_min_timestamp &&
		    !disconnect_clients) {
			/* wait for the next user's event */
			break;
		}
		user_run_actions(*userp);
	}
	/* make sure a timeout is always set */
	if (to_users == NULL)
		users_timeout_update();
}

static void users_timeout_update(void)
{
	if (to_users != NULL)
		timeout_remove(&to_users);
	if (users_min_timestamp <= ioloop_time)
		to_users = timeout_add_short(500, users_timeout, (void *)NULL);
	else {
		to_users = timeout_add((users_min_timestamp - ioloop_time) * 1000,
				       users_timeout, (void *)NULL);
	}
}

static void user_set_min_timestamp(struct user *user, time_t min_timestamp)
{
	if (min_timestamp <= 0)
		return;
	if (min_timestamp <= ioloop_time) {
		/* always set timestamps to future so we don't run the timeout
		   multiple times within second (which is bad if users are
		   sorted multiple times a second) */
		min_timestamp = ioloop_time;
	}
	if (user->next_min_timestamp > min_timestamp)
		user->next_min_timestamp = min_timestamp;
	if (users_min_timestamp > min_timestamp) {
		users_min_timestamp = min_timestamp;
		users_timeout_update();
	}
}

static void
user_add_client_profile(struct user *user, struct profile_client *profile)
{
	struct user_client *uc;

	uc = p_new(user->pool, struct user_client, 1);
	uc->user = user;
	uc->profile = profile;
	p_array_init(&uc->clients, user->pool, 4);
	p_array_init(&uc->mailboxes, user->pool, 2);
	array_append(&user->clients, &uc, 1);
}

static void
user_init_client_profiles(struct user *user, struct profile *profile)
{
	struct profile_client *const *clientp;

	p_array_init(&user->clients, user->pool,
		     array_count(&profile->clients));
	while (array_count(&user->clients) == 0) {
		array_foreach(&profile->clients, clientp) {
			if ((unsigned int)i_rand() % 100 < (*clientp)->percentage)
				user_add_client_profile(user, *clientp);
		}
	}
}

static void
users_add_from_user_profile(const struct profile_user *user_profile,
			    struct profile *profile, ARRAY_TYPE(user) *users,
			    struct mailbox_source *source)
{
	static struct var_expand_table tab[] = {
		{ 'n', NULL, NULL },
		{ '\0', NULL, NULL }
	};
	const char *error;
	struct user *user;
	string_t *str = t_str_new(64);
	unsigned int i;
	time_t start_time;
	char num[10];

	tab[0].value = num;

	for (i = 1; i <= user_profile->user_count; i++) {
		start_time = ioloop_time + profile->rampup_time *
			i / user_profile->user_count;

		str_truncate(str, 0);
		i_snprintf(num, sizeof(num), "%u",
			   user_profile->username_start_index + i-1);
		if (var_expand(str, user_profile->username_format, tab,
			       &error) < 0)
			i_error("var_expand(%s) failed: %s",
				user_profile->username_format,
				error);
		user = user_get(str_c(str), source);
		user->profile = user_profile;
		user_init_client_profiles(user, profile);
		user_fill_timestamps(user, start_time);
		array_append(users, &user, 1);
	}
}

void profile_add_users(struct profile *profile, ARRAY_TYPE(user) *users,
		       struct mailbox_source *source)
{
	struct profile_user *const *userp;

	i_array_init(users, 128);
	array_foreach(&profile->users, userp)
		users_add_from_user_profile(*userp, profile, users, source);
}

void profile_deinit(void)
{
	if (to_users != NULL)
		timeout_remove(&to_users);
}
