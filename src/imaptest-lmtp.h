#ifndef IMAPTEST_LMTP_H
#define IMAPTEST_LMTP_H

bool imaptest_lmtp_have_deliveries(void);

struct profile;

void imaptest_lmtp_send(struct profile *profile,
			unsigned int port, unsigned int lmtp_max_parallel_count,
			const struct smtp_address *rcpt_to, struct mailbox_source *source);
void imaptest_lmtp_delivery_deinit(void);

#endif
