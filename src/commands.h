#ifndef COMMANDS_H
#define COMMANDS_H

#include "seq-range-array.h"
#include "client-state.h"

#include <sys/time.h>

enum command_reply { REPLY_BAD, REPLY_OK, REPLY_NO, REPLY_CONT };

struct imap_client;
struct command;

struct command {
  char *cmdline;
  unsigned int cmdline_len; /* in case there are NUL chars */
  long request_ts;
  enum client_state state;
  unsigned int tag;
  ARRAY_TYPE(seq_range) seq_range;
  void *cb_param;

  command_callback_t *callback;
  struct timeval tv_start;

  bool expect_bad : 1;
};

struct command *command_send_with_param(struct imap_client *client, const char *cmdline, command_callback_t *callback,
                                        void *cb_param);

struct command *command_send(struct imap_client *client, const char *cmdline, command_callback_t *callback);
struct command *command_send_binary(struct imap_client *client, const char *cmdline, unsigned int cmdline_len,
                                    command_callback_t *callback, void *cb_param);

void command_unlink(struct imap_client *client, struct command *cmd);
void command_free(struct command *cmd);

struct command *command_lookup(struct imap_client *client, unsigned int tag);

#endif
