#ifndef SEARCH_H
#define SEARCH_H

struct imap_client;

void search_command_send(struct imap_client *client);
void search_result(struct imap_client *client, const struct imap_arg *args);

#endif
