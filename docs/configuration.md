---
layout: doc
---

# ImapTest Configuration

ImapTest is controlled via command-line flags in the format `<cmd>=<value>`.

:::tip
Settings marked as `boolean` are enabled by providing any value, e.g., `1`.
:::

## Parameters (Primary)

### `host`

* Default: `127.0.0.1`

Host name/IP address where to connect.

### `mbox`

* Default: `~/mail/dovecot-crlf`

Path to mbox file where to append messages from.

See [below](#append-mbox) for how this is used.

### `mech`

 * Default: login

Authentication mechanism to use. This supports anything Dovecot's SASL library does,
for example plain, digest-md5 or scram-sha-1. The pass parameter must match what
the mechanism expects.

### `pass`

* Default: \<none\>

Password to use for all users.

::: warning
There's currently no way to use different passwords for different users on
the command line. Use [`userfile`](#userfile) if you need that functionality.
:::

### `port`

* Default: `143`

Port to connect to.

### `user`

* Default: `$USER`

Username template.

You can use multiple random users and domains by giving `%d` in the template. So for example `user%d` returns `user1..user100` and `user%d@domain%d.org` returns `user1..100@domain1..100.org`.

The upper limit for users can be set with the [`users`](#users) parameter, and the upper limit for domains can be set with the [`domains`](#domains) parameter.

### `userfile`

* Default: \<none\>

Read usernames from given file, one user per line. It's also possible to give passwords for users in `username:password` format.

## Other Parameters

### `box`

* Default: `INBOX`

Mailbox to use for testing.

### `clients`

* Default: `10`

Number of simultaneous client connections to use.

### `copybox`

* Default: \<none\>

When testing COPY state, this specifies the destination mailbox.

### `disconnect_quit`

* Default: no (`boolean` setting)

If a client gets disconnected, quit. This is useful when debugging problems in the server.

### `domains`

* Default: `100`

The upper limit for domain substitution in templates.

### `error_quit`

* Default: no (`boolean` setting)

If an error occurs, immediately quit.

### `master`

* Default: \<none\>

Use master user logins. Value is the masteruser to use.

### `msgs`

* Default: `30`

Try to keep the mailbox size around this many messages.

### `no_pipelining`

* Default: no (`boolean` setting)

If set, don't send multiple commands at once to server.

### `qresync`

* Default: no (`boolean` setting)

If set, enable QRESYNC IMAP extension.

### `imap4rev2`

* Default: no (`boolean` setting)

If set, enable the use of IMAP4rev2.


### `random_msg_size`

* Default: `0`

If set, generates random garbage mails, of this size bytes, instead of using the mail messages supplied by the [`mbox`](#mbox) parameter.

See [below](#append-mbox) for how this is used.

### `rawlog`

* Default: no (`boolean` setting)

Write rawlog.\* files for all connections containing their input and output.

### `results_output`

* Default: no (output to stdout)

If set, results are output to the filename provided.

### `secs`

* Default: \<none\>

Run ImapTest `n` seconds and then exit.

::: warning
Setting this to less than the time to run all scripts with `tests=dir` will lead to spurious test failures.
:::

### `seed`

* Default: \<none\>

Seed to use for random generator. Setting this to some specific value makes repeated benchmarks a bit more reliable, because the used commands should be the same.

### `ssl`

* Default: \<none\>

If set, activate SSL/TLS.

If set to the value `any-cert`, allow invalid certificates.

### `stalled_disconnect_timeout`

* Default: `0` (disabled)

If set, disconnect after this many seconds in a stalled situation.

### `users`

* Default: `100`

The upper limit for user substitution in templates.

## Test Selection

### State Probabilities

Format: `<state>=<probability>[,<probability2>]`

The state probabilities to use. See [States](/states) for further information.

### `checkpoint`

* Default: \<none\>

Run a checkpoint every `n` seconds.

### `no_tracking`

* Default: no (`boolean` setting)

Don't track and complain about IMAP state. Makes it use less memory.

### `own_flags`

* Default: no (`boolean` setting)

Assigns an owner client for each flag and keyword. Complain if they're changed by another session.

### `own_msgs`

* Default: no (`boolean` setting)

Assigns an owner client for each message. Complain if flags for a message is changed by a non-owner session.

### `profile`

* Default: no

If set, use configuration from the profile file provided to run the tests.

See [Profile](/profile) page for additional information on this mode.

### `random`

* Default: no (`boolean` setting)

Switch randomly between states instead of consecutively going through them.

### `test`

* Default: \<none\>

Run [scripted tests](/scripted_test) from a given directory instead of doing stress testing.

## Append Mbox

When saving messages, ImapTest needs to get the messages from somewhere. [`mbox`](#mbox) parameter specifies path to a file in mbox format that's used.

Messages are sequentially appended from there. Once ImapTest reaches the last message, it wraps back to appending the first message.

Currently ImapTest's state tracking expects that Message-IDs are unique within the mbox, otherwise it gives bogus errors. If you really want to avoid changing the Message-IDs, use [`no_tracking`](#no-tracking) setting to disable state tracking.

::: tip
You can get a test mbox file from https://www.dovecot.org/tmp/dovecot-crlf. It's a 10MB file containing messages from Dovecot mailing list with unique Message-ID headers.
:::
