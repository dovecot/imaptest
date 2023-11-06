---
layout: doc
---

# ImapTest Profile

The profile configuration allows definition of the usage profiles for the
test users and clients that are connecting to the server.

The profile configuration is passed to imaptest via the
[`profile`](/configuration#profile) parameter.

::: info
Duration settings are parsed the same as
[Dovecot time settings](https://doc.dovecot.org/settings/types/#time).
:::

## Global Parameters

### `lmtp_port`

* Default: \<none\> (**REQUIRED**)

Port number to use for LMTP. The host is assumed to be the same as for IMAP.

### `lmtp_max_parallel_count`

* Default: `0` (unlimited)

Maximum number of concurrent LMTP connections.

::: info
Should be about half of desired LMTP deliveries per second.
:::

``total_user_count`` = how many users we are using

### `rampup_time`

* Default: `0s`

Spread the initial connections at startup equally to this time period (in
seconds). This way there's not a huge connection spike at startup that
overloads the server.

::: tip
This should generally be at least 5 to 10 seconds to distribute the load
during the actual testing, since it also affects the timing between
connections for the users.
:::

### `total_user_count`

* Default \<none\> (**REQUIRED**)

Total number of users used for the test. This is divided between user {}
definitions according to their count=n% settings.


## User Definitions

User profiles describe how the emulated users are expected to behave. There
can be one or more user profiles.

::: warning
There must be at least one user profile defined.
:::

User profiles are defined within configuration "blocks" prefixed by `user`.
Configuration blocks may have an optional identifier. Example:

```
user aggressive {
   [... user configuration ...]
}
```

### `count`

* Default: \<none\> (**REQUIRED**)

Percentage of [`total_user_count`](#total-user-count) to assign for this user
profile.

::: info
The total value of this setting from all user profiles MUST equal `100%`.
Set to `100%` if there is only one user profile defined.
:::

### `mail_action_delay`

* Default: `0 secs`

How quickly user acts on an incoming email. This is calculated from the
time the user's IMAP connection has seen the new message and FETCHed its
metadata. This may be a long time after the actual mail delivery in case
all users don't have active IMAP connections all the time.

### `mail_action_repeat_delay`

* Default: `0 secs`

After the initial action, how quickly is the next action performed.

### `mail_inbox_delete_percentage`

* Default: `0%`

Chance a mail is marked as \Deleted and UID EXPUNGEd.

Applied to incoming mails. Multiple actions can be performed on the same mail.

### `mail_inbox_delivery_interval`

* Default: \<unlimited\>

How often emails are delivered to INBOX.

::: tip
Deliveries per second is roughly defined by 
[`total_user_count`](#total-user-count) divided by this value. If using
multiple user profiles, deliveries per profile will need to be reduced based
on the user profile's [`count`](#count) value.
:::

### `mail_inbox_move_filter_percentage`

* Default: \<unlimited\>

Likelyhood of incoming mail being moved to Spam mailbox immediately when
noticed by the IMAP client.

[`mail_action_delay`](#mail-action-delay) does NOT affect this action.

### `mail_inbox_move_percentage`

* Default: `0%`

Chance a mail is moved to Spam.

Applied to incoming mails. Multiple actions can be performed on the same mail.

### `mail_inbox_reply_percentage`

* Default: `0%`

Chance a mail is replied to: APPEND via Drafts and Sent mailboxes and add
\Answered flag.

Applied to incoming mails. Multiple actions can be performed on the same mail.

### `mail_send_interval`

* Default: `0` (no outgoing mail sent)

How often outgoing mails are sent. The mail is initially written to the
Drafts mailbox, and after [`mail_write_duration`](#mail-write-duration) it's
written to the Sent mailbox and deleted from Drafts.

### `mail_session_length`

* Default: \<unlimited\>

How long the connection is kept open before disconnecting.

### `mail_spam_delivery_interval`

* Default: \<unlimited\>

How often emails are delivered to Spam.

### `mail_write_duration`

* Default: `0 secs`

How long after mail is written to Drafts mailbox that it is sent.

See [`mail_send_interval`](#mail-send-interval).

### `userfile`

* Default: \<none\> (either this setting or [`username_format`](#username_format) must be set)

A list of usernames from a file.

Each line in the file contains either "username" or "username:password". If
password isn't specified, the global password is used.

This setting overrides [`username_format`](#username-format) and
[`username_start_index`](#username-start-index) settings.

### `username_format`

* Default: \<none\> (either this setting or [`userfile`](#userfile) must be set)

Username template format.

`%n` expands to the user index number. See [`username_start_index`](#username-start-index). Padding can be defined by specifying `<padding character><padding length>` after the '%'.

::: info
Example: `username_format = test_%03n@example.com` means that the calculated
index will be padded to 3 numbers (with 0's). If `total_user_count = 500`,
the generated users would be `test_001@example.com` to `test_500@example.com`.
:::

### `username_start_index`

* Default: `1`

The first index number to use for users in this profile. Usually different
user profiles should either not overlap or overlap only partially (to
describe users who have different behaviors with different clients).

## Client Definitions

Client profiles describe how the emulated clients are expected to behave.
There can be one or more client profiles.

::: warning
There must be at least one client profile defined.
:::

Client profiles are defined within configuration "blocks" prefixed by `client`.
Configuration blocks may have an optional identifier. Example:

```
client Thunderbird {
   [... client configuration ...]
}
```

### `connection_max_count`

* Default: `0`

How many connections should a single user have in parallel.

For POP3 this should be `1`.

### `count`

* Default: \<none\> (**REQUIRED**)

Percentage of [`total_user_count`](#total-user-count) to assign for this client
profile.

::: info
The total value of this setting from all client profiles MUST equal `100%`.
Set to `100%` if there is only one client profile defined.
:::

### `imap_fetch_immediate`

* Default: \<none\>

The FETCH fields the IMAP client should download on initial delivery.

### `imap_fetch_manual`

* Default: \<none\>

The FETCH fields the IMAP client should download on an emulated mail access.

### `imap_idle`

* Default: no 

Does the IMAP client support IDLE?

Boolean setting: enabled by providing any value, e.g., `1`.

### `login_interval`

* Default: `0 secs`

How often should the user log in.

::: info
For example, if this is set to `1s` and you have `count = 100%` and
`total_user_count = 500`, you should have approximately 500 logins per second.
:::

### `pop3_keep_mails`

* Default: no

Keep mails in ``INBOX`` at the end of the session or delete everything?

Boolean setting: enabled by providing any value, e.g., `1`.

### `protocol`

* Default: `imap`

Set to `pop3` if the client should connect via POP3.

IMAP clients are controlled by `imap_*` settings in this section.

POP3 clients are controlled by `pop3*` settings in this section.


## Examples

See `profile.conf` and `pop3-profile.conf` in the source for basic, example
configurations.

A more advanced configuration example:

```
lmtp_port = 24
lmtp_max_parallel_count = 175
total_user_count = 500
rampup_time = 5s
  
user aggressive {
  username_format = testuser_%03n@example.com
  username_start_index = 501
  count = 10%
  
  mail_inbox_delivery_interval = 5s
  mail_spam_delivery_interval = 0
  mail_action_delay = 2s
  mail_action_repeat_delay = 1s
  mail_session_length = 3 min
  
  mail_send_interval = 0
  mail_write_duration = 0
  
  mail_inbox_reply_percentage = 50
  mail_inbox_delete_percentage = 5
  mail_inbox_move_percentage = 5
  mail_inbox_move_filter_percentage = 10
}
  
user normal {
  username_format = testuser_%03n@example.com
  username_start_index = 501
  count = 90%
  
  mail_inbox_delivery_interval = 120s
  mail_spam_delivery_interval = 0
  mail_action_delay = 3 min
  mail_action_repeat_delay = 10s
  mail_session_length = 20 min
  
  mail_send_interval = 0
  mail_write_duration = 0
  
  mail_inbox_reply_percentage = 0
  mail_inbox_delete_percentage = 80
  mail_inbox_move_percentage = 5
  mail_inbox_move_filter_percentage = 10
}
  
client Thunderbird {
  count = 80%
  connection_max_count = 2
  imap_idle = yes
  imap_fetch_immediate = UID RFC822.SIZE FLAGS BODY.PEEK[HEADER.FIELDS (From To Cc Bcc Subject Date Message-ID Priority X-Priority References Newsgroups In-Reply-To Content-Type)]
  imap_fetch_manual = RFC822.SIZE BODY[]
}
  
client AppleMail {
  count = 20%
  connection_max_count = 2
  imap_idle = yes
  imap_fetch_immediate = INTERNALDATE UID RFC822.SIZE FLAGS BODY.PEEK[HEADER.FIELDS (date subject from to cc message-id in-reply-to references x-priority x-uniform-type-identifier x-universally-unique-identifier)] MODSEQ
  imap_fetch_manual = BODYSTRUCTURE BODY.PEEK[]
}
```
