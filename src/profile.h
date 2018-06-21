#ifndef PROFILE_H
#define PROFILE_H

#include "user.h"

#define PROFILE_MAILBOX_SPAM "INBOX.Spam"
#define PROFILE_MAILBOX_DRAFTS "INBOX.Drafts"
#define PROFILE_MAILBOX_SENT "INBOX.Sent"

struct imap_arg;
struct imap_client;

struct profile_client {
	const char *name;
	const char *protocol;
	unsigned int percentage;
	unsigned int connection_max_count;
	bool pop3_keep_mails;
	bool imap_idle;
	const char *imap_fetch_immediate;
	const char *imap_fetch_manual;
	const char *imap_search_query;
	unsigned int imap_status_interval;
	unsigned int login_interval;
};
ARRAY_DEFINE_TYPE(profile_client, struct profile_client *);

struct profile_user {
  struct profile *profile;
  const char *name;
  const char *username_format;
  unsigned int percentage, user_count, username_start_index;

  /* This is kind of tricky. we have connections for: a) desktop clients
     keeping them open ~forever, b) laptop clients keeping them open
     while the laptop is open, c) mobile clients either using IDLE or
     doing logins every n minutes to check for mails. For now this
     one setting is all we have.. */
  unsigned int mail_session_length;

  /* How often to deliver mails to this user's INBOX/Spam
     (approximately) */
  unsigned int mail_inbox_delivery_interval;
  unsigned int mail_spam_delivery_interval;
  /* How often user writes a new mail (saved to Sent) */
  unsigned int mail_send_interval;

  /* When a new mail is delivered to INBOX, what are the probabilities of
     the action that is done to it (0-100, with total <= 100) */
  unsigned int mail_inbox_reply_percentage;
  unsigned int mail_inbox_delete_percentage;
  unsigned int mail_inbox_move_percentage;

  unsigned int mail_inbox_search_percentage;
  /* Same as "move", but this is done immediately instead of after
     mail_action_delay. */
  unsigned int mail_inbox_move_filter_percentage;

  /* How long to wait before user reacts to the mail */
  unsigned int mail_action_delay;
  /* How long to wait between user's reactions to mail (fetch body ->
     [fetch body for more mails .. ->] do actions */
  unsigned int mail_action_repeat_delay;
  /* How long a user spends writing a mail approximately
     (and getting mail saved to Drafts) */
  unsigned int mail_write_duration;
  /* How large mails does the user typically write */
  uoff_t mail_write_size;
};
ARRAY_DEFINE_TYPE(profile_user, struct profile_user *);

struct profile {
	pool_t pool;
	const char *path;

	ARRAY_TYPE(profile_user) users;
	ARRAY_TYPE(profile_client) clients;
	unsigned int lmtp_port;
	unsigned int lmtp_max_parallel_count;
	unsigned int total_user_count;
	unsigned int rampup_time;
};

struct profile *profile_parse(const char *path);
int imap_client_profile_send_more_commands(struct client *client);
int imap_client_profile_handle_untagged(struct imap_client *client,
					const struct imap_arg *args);

void profile_add_users(struct profile *profile, ARRAY_TYPE(user) *users,
		       struct mailbox_source *source);

void profile_deinit(void);

#endif
