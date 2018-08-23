#ifndef CLIENT_STATE_H
#define CLIENT_STATE_H

#include "seq-range-array.h"

enum command_reply;
struct timeval;
struct client;
struct imap_client;
struct command;
struct imap_arg;

enum login_state { LSTATE_NONAUTH, LSTATE_AUTH, LSTATE_SELECTED };

enum client_state {
  STATE_BANNER,
  STATE_AUTHENTICATE,
  STATE_LOGIN,
  STATE_LIST,
  STATE_MCREATE,
  STATE_MDELETE,
  STATE_MSUBS,
  STATE_STATUS,
  STATE_SELECT,
  STATE_UIDFETCH,
  STATE_FETCH,
  STATE_FETCH2,
  STATE_SEARCH,
  STATE_SORT,
  STATE_THREAD,
  STATE_COPY,
  STATE_STORE,
  STATE_STORE_DEL,
  STATE_EXPUNGE,
  STATE_APPEND,
  STATE_NOOP,
  STATE_IDLE,
  STATE_CHECK,
  STATE_LOGOUT,
  STATE_DISCONNECT,
  STATE_DELAY,
  STATE_CHECKPOINT,
  STATE_LMTP,
  STATE_GET_METADATA,
  STATE_COUNT
};

enum state_flags {
  FLAG_MSGSET = 0x01,
  FLAG_EXPUNGES = 0x02,
  FLAG_STATECHANGE = 0x04,
  FLAG_STATECHANGE_NONAUTH = 0x08,
  FLAG_STATECHANGE_AUTH = 0x10,
  FLAG_STATECHANGE_SELECTED = 0x20
};

struct state {
  const char *name;
  const char *short_name;
  enum login_state login_state;
  unsigned int probability;
  unsigned int probability_again;
  enum state_flags flags;
  long avg_msg_time;
  long ts_request;
};

enum client_random_flag_type {
  CLIENT_RANDOM_FLAG_TYPE_NONE,
  CLIENT_RANDOM_FLAG_TYPE_FETCH,
  CLIENT_RANDOM_FLAG_TYPE_STORE,
  CLIENT_RANDOM_FLAG_TYPE_STORE_SILENT
};
#define NUM_BAD_STATES 3

typedef void command_callback_t(struct imap_client *client, struct command *cmd, const struct imap_arg *args,
                                enum command_reply reply);

extern struct state states[STATE_COUNT];
extern unsigned int counters[STATE_COUNT], total_counters[STATE_COUNT];
extern unsigned int timer_counts[STATE_COUNT];
extern unsigned long long timers[STATE_COUNT];
extern float mean[STATE_COUNT];
extern int bad_requests;

bool do_rand(enum client_state state);
bool do_rand_again(enum client_state state);
void client_state_add_to_timer(enum client_state state, const struct timeval *tv_start);

int imap_client_append(struct imap_client *client, const char *args, bool add_datetime, command_callback_t *callback,
                       struct command **cmd_r);
int imap_client_append_full(struct imap_client *client, const char *mailbox, const char *flags, const char *datetime,
                            command_callback_t *callback, struct command **cmd_r);
int imap_client_append_random(struct imap_client *client);
int imap_client_append_continue(struct imap_client *client);
int imap_client_plan_send_next_cmd(struct imap_client *client);
int imap_client_plan_send_more_commands(struct client *client);

void imap_client_handle_resp_text_code(struct imap_client *client, const struct imap_arg *args);
void imap_client_handle_tagged_reply(struct imap_client *client, struct command *cmd, const struct imap_arg *args,
                                     enum command_reply reply);

bool imap_client_get_random_seq_range(struct imap_client *client, ARRAY_TYPE(seq_range) * range, unsigned int count,
                                      enum client_random_flag_type flag_type);

void state_callback(struct imap_client *client, struct command *cmd, const struct imap_arg *args,
                    enum command_reply reply);
void fetch_state_callback(struct imap_client *client, struct command *cmd, const struct imap_arg *args,
                          enum command_reply reply);
void imap_client_cmd_reply_finish(struct imap_client *client);

extern float calculate_mean(long current_value, float old_mean, unsigned int count);

#endif
