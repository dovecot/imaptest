---
layout: doc
---

# Test Features

## State Tracking Features

ImapTest should catch the following errors:

* Referring to sequences that haven't been announced with EXISTS.
* Sequence <-> UID map changes unexpectedly
* Message's static metadata changes unexpectedly. Messages are uniquely identified by their Message-ID: header.
   * BODY, BODYSTRUCTURE, ENVELOPE and RFC822.SIZE are currently tracked.
   * "BODY[HEADER.FIELDS (..)]" are tracked for some headers.
   * IMAP servers handle FETCHes for expunged messages differently. ImapTest tries to catch these.
* Message's INTERNALDATE changes unexpectedly.
* FETCH FLAGS listing keywords that haven't been announced with untagged FLAGS.
* Untagged FLAGS reply dropping a keyword that's still in use.
* Flags or keywords changed unexpectedly (when [`own_msgs`](/configuration#own-msgs) enabled)
* Non-atomic flag or keyword updates. For example if session 1 does "STORE +FLAGS \Seen" and session 2 does "STORE +FLAGS \Draft" at the same time, with some servers the result may be either \Seen or \Draft instead of both. Testing this requires enabling [`own_flags`](/configuration#own-flags).
* SEARCH correctness. Currently supports checking: sequences, SMALLER, LARGER, BEFORE, ON, SINCE.
* Message's MODSEQ shrinks (CONDSTORE) or is changed unexpectedly (when [`own_msgs`](/configuration#own-msgs) enabled)
* Using QRESYNC loses changes (when [`qresync`](/configuration#qresync) and [`checkpoint`](/configuration#checkpoint) enabled)

Checkpointing works by letting all the pending commands finish. Then CHECK command is sent to all sessions. Once they're done, ImapTest verifies that all clients' mailbox state looks exactly the same:

* Number of messages is the same
* Sequence <-> UID map is the same
* Flags and keywords are the same
* MODSEQs are the same (if CONDSTORE or QRESYNC is enabled)
* \Recent flag for a message exists in only one session (all mailboxes are SELECTed currently)
* \Recent flag for a message has never existed. This works only if we know flags for all messages (so FETCH is required also). Expunging less often (e.g., `expunge=10`) makes this check work better.
* Summing up RECENT count from all sessions matches the message count. This is done only if at some point one session's RECENT count has matched message count. ImapTest tries to make this happen by expunging all existing messages from mailbox.
