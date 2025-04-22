#ifndef MAILBOX_STATE_H
#define MAILBOX_STATE_H

struct imap_client;

void mailbox_state_handle_fetch(struct imap_client *client, unsigned int seq,
				const struct imap_arg *args);

int mailbox_state_set_flags(struct mailbox_view *view,
			    const struct imap_arg *args,
			    bool imap4rev2_enabled);
int mailbox_state_set_permanent_flags(struct mailbox_view *view,
				      const struct imap_arg *args,
				      bool imap4rev2_enabled);

#endif
