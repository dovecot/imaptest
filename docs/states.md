---
layout: doc
---

# ImapTest States

By default, ImapTest runs through all the states in the order specified in the table below. Each command is run with the given probability. If it's not run, it skips to the next command and performs the same check for it.

Only commands that are valid in the current connection state can be processed, of course. Using [`random`](/configuration#random) parameter will randomize the order of commands in [`selected`](/scripted_test#state) state completely, so:

1. Randomized command is chosen, AND
1. Probability check will determine if it's used or the next random command will be attempted.

States can be specified using full or short names. You specify the probabilities in percents, so `list=30` means that LIST command is executed with 30% probability.

The second probability is mainly useful for APPEND, where it controls how often to append multiple messages with MULTIAPPEND extension. `append=80,30` means that APPEND command is executed with 80% probability, and after each appended message there's a 30% chance of the APPEND command continuing.

You can disable all except LOGIN, LOGOUT and SELECT states by giving `-` parameter. For example: `imaptest - select=0 append=100,0 logout=0` will do nothing but a LOGIN followed by APPENDs.

| Name           | Short name | Default % | Description                                                                 |
| -------------- | ---------- | --------- | --------------------------------------------------------------------------- |
| `AUTHENTICATE` | `Auth`     | `0`       | Authentication with "AUTHENTICATE PLAIN" command                            |
| `LOGIN`        | `Logi`     | `100`     | Authentication with LOGIN command                                         |
| `COMPRESS`     | `Comp`     | `0`       | Enable IMAP COMPRESS                                                        |
| `LIST`         | `List`     | `50`      | 'LIST "" \*'                                                                 |
| `MCREATE`      | `LCre`     | `0`       | CREATE test/x/y mailboxes randomly. `/` separator is hardcoded currently. |
| `MDELETE`      | `LDel`     | `0`       | DELETE test/x/y mailboxes randomly                                        |
| `MSUBS`        | `MSub`     | `0`       | SUBSCRIBE and UNSUBUSCRIBE test/x/y mailboxes randomly                  |
| `STATUS`       | `Stat`     | `50`      | "STATUS (MESSAGES UNSEEN RECENT)"                                           |
| `SELECT`       | `Sele`     | `100`     | SELECT mailbox (required for most states below)                           |
| `UIDFETCH`     | `UIDF`     | `0`       | "UID FETCH 1:\* FLAGS"; This is run only once per session. The probability specifies how likely the first time happens. |
| `FETCH`        | `Fetc`     | `100`     | "FETCH n:m" (random fields) where n:m is a range with random start for 100 messages (or all messages if mailbox has less than 100 messages). Randomly fetched fields are: UID, FLAGS, ENVELOPE, INTERNALDATE, BODY, BODYSTRUCTURE, and "BODY.PEEK[HEADER.FIELDS (random headers)]". Random headers are: From, To, Cc, Subject, Message-ID, In-Reply-To, References, and Delivered-To. |
| `FETCH2`       | `Fet2`     | `100,30`  | "FETCH n (BODY.PEEK[])", where n is a random message                        |
| `SEARCH`       | `Sear`     | `0`       | "SEARCH \<random search query\>" where the query can contain multiple parameters, including ORs and parenthesis. It randomly choses among: SMALLER, LARGER, BEFORE, ON, SINCE, SENTBEFORE, SENTON, SENTSINCE, SUBJECT, TEXT, and BODY. |
| `SORT`         | `Sort`     | `0`       | "SORT (SUBJECT) US-ASCII" for ALL or FLAGGED randomly                   |
| `THREAD`       | `Thre`     | `0`       | "THREAD REFERENCES US-ASCII ALL"                                            |
| `COPY`         | `Copy`     | `33,5`    | COPY random number of messages                                            |
| `STORE`        | `Stor`     | `50`      | "STORE \<random-range\> [+-]FLAGS[.SILENT] \<random flags and keywords\>". Only `$Label1..5` are used as keywords. SILENT is used if checkpointing is disabled. \Deleted flags aren't set. |
| `DELETE`       | `Dele`     | `100`     | "STORE \<random-range\> +FLAGS[.SILENT] \Deleted"                             |
| `EXPUNGE`      | `Expu`     | `100`     | EXPUNGE                                                                   |
| `APPEND`       | `Appe`     | `100,5`   | APPEND messages to mailbox. MULTIAPPEND extension is used if possible. The counter shows number of APPEND commands, so with MULTIAPPEND it doesn't match the actual number of appended messages. |
| `NOOP`         | `Noop`     | `0`       | NOOP                                                                      |
| `IDLE`         | `Idle`     | `0`       | IDLE command. The finishing DONE is sent before the next command. This doesn't add any extra waits/delays. |
| `CHECK`        | `Chec`     | `0`       | CHECK command                                                             |
| `LOGOUT`       | `Logo`     | `100`     | LOGOUT command                                                            |
| `DISCONNECT`   | `Disc`     | `0`       | Disconnect without LOGOUT                                                 |
| `DELAY`        | `Dela`     | `0`       | Random 0..999 millisecond delay                                             |
| `CHECKPOINT!`  | `ChkP`     | `0`       | Use checkpoint parameter to change this. The counter shows number of client connections successfully checkpointed. |
