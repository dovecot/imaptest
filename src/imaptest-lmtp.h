#ifndef IMAPTEST_LMTP_H
#define IMAPTEST_LMTP_H

void imaptest_lmtp_send(unsigned int port, unsigned int lmtp_max_parallel_count,
			const char *rcpt_to, struct mailbox_source *source);
void imaptest_lmtp_delivery_deinit(void);

#endif
