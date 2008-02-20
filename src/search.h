#ifndef SEARCH_H
#define SEARCH_H

void search_command_send(struct client *client);
void search_result(struct client *client, const struct imap_arg *args);

#endif
