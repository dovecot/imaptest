---
layout:doc
---

# Scripted Testing Configuration

The tests consist of two files in the test directory:

* `<name>`
* `<name>.mbox`

The test file begins with a header, followed by an empty line and then a list of commands. Messages are appended to the test mailbox from the `<name>.mbox` file.

::: danger
Unless the [state](#state) value is set to `nonauth`, running a scripted
tests is a destructive action (all existing messages will be deleted) for
all configured test mailboxes!
:::

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

::: warning
`nonauth` is the only state that will not delete all existing messages in
the test mailbox.
:::

### `user <N>`

* Default: \<none\>

Sets the username template for connection `<N>` (where `<N>` is a positive integer). This is useful when testing with different accounts on multiple connections. The value is typically set to `${user2}`, `${user3}`, etc. to use the username templates configured via command-line parameters.

### `ignore_extra_untagged`

* Default: `yes`

If `no`, require that all the untagged replies are explicitly listed in the script. If `yes`, untagged replies are ignored.

## Commands

There are three ways to configure commands:

### Method 1

```
[<connection #>] OK|NO|BAD|"" <command>
[* <tagged reply>] (0 or more)
```

* This method is generally fastest to write.
* Connection number (`<connection #>`) is used if there is more than one connection.
* The order of untagged replies doesn't matter.

#### Example

```
ok select $mailbox
* 0 exists
```

### Method 2

```
[<connection #>] <command>
[* <tagged reply>] (0 or more)
[<connection #>] OK|NO|BAD|"" [<prefix>]
```

* This method allows matching reply's `<prefix>`.
* Connection number (`<connection #>`) is used if there is more than one connection.
* The order of untagged replies doesn't matter.

#### Example

```
select $mailbox
* 0 exists
1 ok [read-write]
```

### Method 3

```
[<connection #>] <tag> <command>
[* <tagged reply>] (0 or more)
[<connection #>] <tag> OK|NO|BAD|"" [<prefix>]
```

* This method is required for pipelining commands.
* Connection number (`<connection #>`) is used if there is more than one connection.
* The order of untagged replies doesn't matter.

#### Examples

##### Pipelined

```
tag1 status ${mailbox} (messages)
tag2 status ${mailbox}2 (messages)
* status ${mailbox} (messages 0)
* status ${mailbox}2 (messages 0)
tag1 ok
tag2 ok
```

##### Pipelined (Multiple Connections)

::: warning
All commands in a pipelined group MUST use the same connection.
:::

```
1 tag1 create ${mailbox}
1 tag2 create ${mailbox}2
1 tag1 ok
1 tag2 ok
```

## Multiline IMAP Literals

Commands and expected server responses can include multiline IMAP literals using <code v-pre>{{{</code> and <code v-pre>}}}</code> block delimiters.

When a line ends with <code v-pre>{{{</code>, all subsequent lines up to <code v-pre>}}}</code> are captured as literal data. The test parser automatically calculates the byte length of the content and replaces the block with standard IMAP literal syntax (`{length}\r\n`).

* **Standard Literals (<code v-pre>{{{</code>)**: Formats the literal as a standard IMAP literal (`{<size>}\r\n`).
* **Binary Literals (<code v-pre>~{{{</code>)**: If preceded by a tilde (<code v-pre>~{{{</code>), the literal is formatted as a binary IMAP literal (`~{<size>}\r\n`).

### Examples

#### Sending a Literal Command

```
ok append $mailbox (\seen \flagged) catenate (text {{{
From: foo@example.com

Hello world

}}})
```

#### Expecting a Literal Response

```
ok fetch 1 (uid body.peek[])
* 1 fetch (uid $uid body[] {{{
From: foo@example.com

Hello world

}}})
```

## Variables

Commands and replies can use `$variables`.

### Dynamic Variables

If a variable doesn't have a value when it's matched against server input, the variable is initialized from the server input and can be reused in subsequent commands. Example:

```
ok fetch 1,2 uid
* 1 fetch (uid $uid1)
* 2 fetch (uid $uid2)

ok uid store $uid1,$uid2 flags \seen
* 1 fetch (uid $uid1 flags (\seen))
* 2 fetch (uid $uid2 flags (\seen))
```

### Escaping and Wildcards

- **Literal Escaping (`$$`)**:
  If you need a literal `$` character in a command or response match without treating it as a variable lookup, escape it by writing `$$`.

- **Wildcard Matching (`$`)**:
  To match any single IMAP argument or list structure without storing it in a variable, use `$`. Example:
  ```
  ok fetch 1 (uid flags)
  * 1 fetch (uid $ flags $)
  ```

- **Bracket Skipping (`$]`)**:
  To skip untagged response tokens until encountering a closing bracket `]`, use `$]`. Example:
  ```
  * OK [CAPABILITY $] Capabilities.
  ```

### Special Variable Matchers

- **Sequence Position UIDs (`$n`)**:
  Using `$n`, where `n` is a number, maps to the UID at sequence position `n` in the current mailbox. These are useful when receiving EXPUNGEs from another session, where sequence numbers may shift. Example:
  ```
  1 ok expunge
  2 ok uid fetch 3 flags
  # server may send expunge before or after fetch - both match this test
  * $2 expunge
  * $3 fetch (uid 3 (flags ()))
  ```

- **Case Sensitivity (`${case:text}`)**:
  Normally all strings are compared case-insensitively. If you need to support case-sensitive matching, use `${case:text}`:
  ```
  ok list "" *
  * LIST () "/" ${case:INBOX/Inbox}
  ```

- **Modseq Variables (`$modseqN`)**:
  Modseq tracking can be done using `$modseqN` variables. They are expected to be listed in an increasing order. Each new value must be at least as high as the gap between the index numbers. For example with `$modseq2` and `$modseq5` the following modseq matches are acceptable:
   * 2, 5
   * 2, 6
   * 10, 13
   * 10, 100

  But the following are not:
   * 1, 5 ($modseq2 must be 2 at minimum)
   * 2, 4 ($modseq5 must be 5 at minimum)
   * 10, 12 ($modseq5 must be 13 at minimum)

### Predefined Variables

There are also predefined runtime variables provided by the test execution environment:

| Variable       | Description                                                                                       |
| -------------- | ------------------------------------------------------------------------------------------------- |
| `$user`        | user@domain                                                                                       |
| `$username`    | User without @domain                                                                              |
| `$domain`      | Domain                                                                                            |
| `$password`    | Password                                                                                          |
| `$mailbox`     | Mailbox used for testing. `box` command line parameter specifies this. The default is `imaptest`. |
| `$mailbox_url` | IMAP URL for the mailbox                                                                          |
| `$tag`         | IMAP command tag for the command (e.g. `1.1`)                                                     |

* If there are multiple connections with different usernames, `$user2`, `$user3`, `$username2`, `$domain2`, `$password2`, etc. are also supported.

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
* "n FETCH (FLAGS ($!unordered $!noextra $!ignore=\recent $!ignore=$HasAttachment $!ignore=$HasNoAttachment))"
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

## Comments

Lines beginning with `#` are treated as comments and ignored by the parser.

```
# This is a comment and will be ignored
ok select $mailbox
```

## Preprocessing

Preprocessing directives allow test files to be conditional, include delays, or produce custom output.

::: info
All directives begin with `!` and must appear on their own line.
:::

### Conditional Execution

| Directive | Description |
| --- | --- |
| `!ifenv <VAR>` | Start a block that runs only if the environment variable `<VAR>` is **set** (regardless of its value). |
| `!ifnenv <VAR>` | Start a block that runs only if the environment variable `<VAR>` is **not set**. |
| `!else` | Toggle the skip state. If the preceding `!ifenv`/`!ifnenv` block was being skipped, the `!else` block is executed and vice versa. Only one `!else` is allowed per `!ifenv`/`!ifnenv` block. |
| `!endif` | End the current `!ifenv`/`!ifnenv` block. The skip state is restored to what it was before the matching `!ifenv`/`!ifnenv`. |

The directives can be nested. Each `!ifenv`/`!ifnenv` must have a matching `!endif`.

```
!ifenv HAVE_FOO
# HAVE_FOO is defined
ok foo
* foo stuff
!else
# HAVE_FOO is NOT defined
ok fallback
* fallback response
!endif

!ifenv HAVE_BAR
!ifenv HAVE_BAZ
# HAVE_BAR and HAVE_BAZ are defined
ok both bar and baz
!endif
!endif
```

### Delay

| Directive | Description |
| --- | --- |
| `!sleep <interval>` | Pause for the specified interval before processing the next command. The interval is specified in milliseconds. |

```
ok some-command
# Delay for 500ms
!sleep 500
ok next-command
```

### Untagged reply order

| Directive | Description |
| --- | --- |
| `!ordered` | Require the untagged replies of this command to be received in the same order as they are listed. |

By default the untagged replies may be received in any order. With
`!ordered` a reply is matched only against the first expected reply that
hasn't been matched yet, so replies arriving in the wrong order are reported
as missing.

```
ok noop
!ordered
* LIST () "." foo
* LIST (\NonExistent) "." foo
```

### Output

| Directive | Description |
| --- | --- |
| `!output <text>` | Print `<text>` to the test output during execution. |

```
# This text will be printed in the test output
!output Starting optional test section
!ifenv HAVE_FOO
ok foo
* foo stuff
!endif
```

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
