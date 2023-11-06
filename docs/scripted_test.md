---
layout:doc
---

# Scripted Testing Configuration

The tests consist of two files in the test directory:

* `<name>`
* `<name>.mbox`

The test file begins with a header, followed by an empty line and then a list of commands. Messages are appended to the test mailbox from the `<name>.mbox` file.

## Header

The header contains `key: value` pairs.


### `capabilities`

* Default: \<none\>

Space-separated list of capabilities required from the server for this test. If server doesn't have these capabilities, the test is skipped.

### `connections`

* Default: `1`

Number of connections to use for executing this test. If using 2 or more connections, each command must begin with the connection number which is used for the command (1..n).

### `messages`

* Default: all messages

How many messages to append to mailbox? If there are more messages than exist in the mbox file, the reading is wrapped to continue from the beginning of the file.

### `state`

* Default: `selected`

Available states (each state does the tasks in the state listed before it):

| State      | Description                                                                          |
| ---------- | ------------------------------------------------------------------------------------ |
| `nonauth`  | Don't authenticate.                                                                  |
| `auth`     | Authenticate and makes sure all test mailboxes are deleted before starting the test. |
| `created`  | Creates the test mailbox.                                                            |
| `appended` | Appends all mails from the test mbox.                                                |
| `selected` | Selects the mailbox.                                                                 |

### `ignore_extra_untagged`

* Default: `yes`

If `no`, require that all the untagged replies are explicitly listed in the script. If `yes`, untagged replies are ignored.

## Commands

There are two ways to configure commands:

### Method 1

```
[<connection #>] OK|NO|BAD|"" <command>
[* <tagged reply>] (0 or more)
```

* Connection number (`<connection #>`) is used if there is more than one connection.
* The order of untagged replies doesn't matter. This method is generally faster to write.

Example:

```
ok select $mailbox
* 0 exists
```

### Method 2

```
[<connection #> <command>
[* <tagged reply>] (0 or more)
OK|NO|BAD|"" [<prefix>]
```

* Connection number (`<connection #>`) is used if there is more than one connection.
* The order of untagged replies doesn't matter. This method allows matching reply's `<prefix>`.

Example:

```
select $mailbox
* 0 exists
1 ok [read-write]
```

## Variables

Commands and replies can have `$variables`.

If a variable doesn't have a value when it's matched against server input, the variable is initialized from the server input. Example:

```
ok fetch 1,2 uid
* 1 fetch (uid $uid1)
* 2 fetch (uid $uid2)

ok uid store $uid1,$uid2 flags \seen
* 1 fetch (uid $uid1 flags (\seen))
* 2 fetch (uid $uid2 flags (\seen))
```

If you want to match the IMAP argument against anything, use `$`. This also works for lists, unlike named variables. Example:

```
ok fetch 1 (uid flags)
* 1 fetch (uid $ flags $)
```

Using `$n`, where `n` is a number, maps to sequences at the beginning of a command. These are useful when receiving EXPUNGEs from another session. Example:

```
1 ok expunge
2 ok uid fetch 3 flags
# server may send expunge before or after fetch - both match this test
* $2 expunge
* $3 fetch (uid 3 (flags ()))
```

### Predefined Variables

There are also some predefined variables:

| Variable       | Description                                                                                       |
| -------------- | ------------------------------------------------------------------------------------------------- |
| `$user`        | user@domain                                                                                       |
| `$username`    | User without @domain                                                                              |
| `$domain`      | Domain                                                                                            |
| `$password`    | Password                                                                                          |
| `$mailbox`     | Mailbox used for testing. `box` command line parameter specifies this. The default is `imaptest`. |
| `$mailbox_url` | IMAP URL for the mailbox                                                                          |

* If there are multiple connections with different usernames, `$user2`, `$user3`, `$username2`, `$domain2`, etc. are also supported.

## Pipelining

Multiple commands can be pipelined:

```
tag1 status ${mailbox} (messages)
tag2 status ${mailbox}2 (messages)
* status ${mailbox} (messages 0)
* status ${mailbox}2 (messages 0)
tag1 ok
tag2 ok
```

## Directives

`$!directives` can be used to alter list matching by placing them at the beginning of a list:

| Directive       | Description                                                                                                                           |
| --------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| `$!ordered`     | The element order in the list must match (default for most lists).                                                                    |
| `$!unordered`   | The element order in the list doesn't matter. Setting this also allows extra elements to be present.                                  |
| `$!unordered=n` | Like `$!unordered`, but list consists of a chain of elements where each chain consists of `n` elements. For example with "FETCH (uid 1 flags (\seen))", the FETCH list would use `$!unordered=2` while the flags list would use `$!unordered`. |
| `$!noextra`     | If `$!unordered[=n]` directive was used, matching ignores extra elements by default. This requires that all elements must be matched. |
| `$!extra`       | Reverse of `$!noextra`.                                                                                                               |
| `$!ignore=e`    | If `$!noextra` is used, allow an extra element `e` to exist in the list.                                                              |
| `$!ban=e`       | If `$!extra` is used, don't allow an extra element `e` to exist in the list.                                                          |

If a list has no explicit directives, defaults are used (separately for each list within same command):

* "n FETCH ($!unordered=2)"
* "n FETCH (FLAGS ($!unordered $!noextra $!ignore=\recent))"
* "LIST ($!unordered)"
* "LSUB ($!unordered)"
* "STATUS mailbox ($!unordered=2)"

::: info
These defaults within the list aren't used at all if any `$!` directives are used. For example:

```
* 1 FETCH (FLAGS ($!extra))
```

is fully expanded as:

```
* 1 FETCH ($!unordered=2 FLAGS ($!extra))
```

So the FLAGS won't have `$!unordered` or `$!ignored=\recent`, but the parent FETCH list will have the default `$!unordered=2`.
:::

## Preprocessing

You can use `!ifenv`, `!ifnenv`, `!else` and `!endif` to run tests only if specified environment variables exist. For example:

```
!ifenv HAVE_FOO
ok foo
* foo stuff
!endif
```

The "foo" command is run only if the `HAVE_FOO` environment variable exists.

Similarly `!ifnenv HAVE_FOO` block is run only if the `HAVE_FOO` environment variable doesn't exist.

## Full Example

```
capabilities: CHILDREN LIST-EXTENDED
connections: 2
state: auth

ok fetch 1,2 uid
* 1 fetch (uid $uid1)
* 2 fetch (uid $uid2)

!ifenv HAVE_FOO
ok foo
* foo stuff
!endif
```
