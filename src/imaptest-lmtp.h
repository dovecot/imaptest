#ifndef IMAPTEST_LMTP_H
#define IMAPTEST_LMTP_H

void imaptest_lmtp_send(unsigned int port, const char *rcpt_to,
			struct mailbox_source *source);
void imaptest_lmtp_delivery_deinit(void);

#endif
