---
layout: doc
---

# IMAP Server Compliancy Status

## Categories

### Checkpoint

* Checkpoint parameter works. When issuing a CHECK command in all sessions, their state looks identical.
   * It would actually be better to be consistent across all IMAP commands, but especially when NOOP or IDLE is used. Some servers have inconsistent IMAP session states because the client connections end up in, e.g., different servers that don't synchronize immediately. This can cause problems with clients that rely on the different sessions seeing the same state.

### Recent Flag

* Exactly one session sees a new message as \Recent - no more and no less.
   * ImapTest prints an error if it notices multiple sessions having the same \Recent flag ("Message seq=.. UID=.. has \Recent flag in multiple sessions"). This happens automatically when running ImapTest with multiple clients for the same user, e.g., `imaptest user=testuser clients=10`.
   * But missing \Recent flags isn't detected with any tests.

### Atomic Flags

* Flags and keywords can be added/removed in multiple sessions without one session dropping changes made by other
   * Test by running stress test with [`own_flags`](/configuration#own-flags) parameter and multiple clients for the same user, e.g., `imaptest user=testuser clients=10 own_flags`
      * If no errors are printed then it's likely ok.

### Expunge Fetch

* If message is expunged in one session, can another session that still sees the message fetch its contents?
   * Yes: Yes, everything can be fetched
   * Cached: Only cached data can be fetched. Message header or body can't be.
   * No: Nothing but flags can be fetched.
   * This needs to be tested manually to see how it behaves - there is no ready imaptest test for this. Manual testing with IMAP:
      * Open two IMAP sessions and "SELECT INBOX" in both
      * Session 1: "STORE 1 +FLAGS \Deleted", EXPUNGE
      * Session 2: "FETCH 1 BODYSTRUCTURE" -> Success = Cached
      * Session 2: "FETCH 1 BODY.PEEK[]" -> Success = Yes

### Expunge Store

* If message is expunged in one session, can another session update its flags?
   * Yes: Yes, and a 3rd session also sees the change
   * Session: Yes, but a 3rd session won't see the change
   * Delayed: Yes, but a 3rd session won't see *any* changes until EXPUNGEs are reported
   * Ignored: STORE command replies OK, but no change is made
   * No: STORE command replies NO
   * This needs to be tested manually to see how it behaves - there is no ready ImapTest test for this. Manual testing with IMAP:
      * Open three IMAP sessions and "SELECT INBOX" in all
      * Session 1: "STORE 1 +FLAGS \Deleted", EXPUNGE
      * Session 2: "STORE 1,2 +FLAGS \Seen"
      * Session 3: "FETCH 1,2 FLAGS"
         * If neither mail shows \Seen flag, run in Session 3 NOOP and "FETCH 1 FLAGS". This should result in EXPUNGE notification and mail 2 showing \Seen flag. This result is delayed.

### Failures (failures/total)
* Number of failures using [scripted tests](/scripted_test). These numbers may not be exact all the time, because the tests are still changing.
   * Failure groups: Each test belongs to a wider group of tests, typically testing a command or part of a command. If this count is low but individual command failure count is high, it probably means that the server has failed to implement wrong only a couple of commands.
   * Base fails: Number of individual base IMAP4rev1 protocol commands that failed.
   * Ext fails: Number of individual IMAP extension commands that failed. Extensions not supported aren't included in the numbers.
   * Test using, e.g., `imaptest user=testuser test=tests/`.


## Server Compliance

::: warning
These results are out-of-date!

### Fully Compliant Servers

| Server | Checkpoint | \Recent | Atomic flags | Expunge fetch | Expunge store | Failure groups | Base fails | Ext fails |
| ------ | ---------- | ------- | ------------ | ------------- | ------------- | -------------- | ---------- | --------- |
| [Dovecot](https://www.dovecot.org/) | Yes | Yes | Yes | Yes / Cached (depends on storage) | Yes | 0/40 | 0/403 | 0/100 |
| [Panda IMAP](https://github.com/jonabbey/panda-imap/) 2008, mix format | Yes | Yes | Yes | Yes | Session | 0/34 | 0/328 | 0/97 |
| [SurgeMail](http://netwinsite.com/surgemail/) 5.0h3 | Yes | Yes | Yes | Yes | Yes | 0/35 | 0/342 | 0/26 |


### Non-Compliant Servers

| Server | Checkpoint | \Recent | Atomic flags | Expunge fetch | Expunge store | Failure groups | Base fails | Ext fails |
| ------ | ---------- | ------- | ------------ | ------------- | ------------- | -------------- | ---------- | --------- |
| [UW-IMAP](http://www.washington.edu/imap/) 2007b, mix format | Yes | Yes | Yes | Yes | Session | 2/34 | 0/328 | 6/53 |
| [Isode M-Box](http://www.isode.com/products/m-box.html) 14.3a0 | No | Unreliable | Yes | Cached | Ignored | 4/40 | 1/408 | 8/112 |
| [CommuniGate Pro](http://www.communigate.com/community/) 5.2.1 | Yes | Yes | Yes | Cached (some) | No | 8/34 | 8/328 | 0/0 |
| [Cyrus](https://www.cyrusimap.org/) 3.0.10 | No | Unreliable | Bugs | Cached | Delayed | 0/35 | 0/366 | 0/100 |
| [Sun Java Messaging Server](http://www.sun.com/software/products/messaging_srvr/index.xml) 6.3-0.15 | No | Unreliable | Bugs | Yes | Delayed | 9/34 | 17/328 | 9/21 |
| [Archiveopteryx](http://www.archiveopteryx.org/) 3.0.3 | No | Unreliable | No | No | No | 13/38 | 25/346 | 6/26 |
| [Courier](http://www.courier-mta.org/imap/) 4.3.1 | Yes | Unreliable | Yes | No | No | 18/34 | 33/328 | 20/53 |
| [GMail](http://www.gmail.com/) 2012-08-12 | No | Not implemented | Bugs | Cached (some) | Ignored | 12/49 | 66/376 | 0/0 |
| [Zarafa Collaboration Platform](http://www.zarafa.com/) 7.1.10 | No | Unreliable | Yes | No | No | 6/35 | 14/340 | 0/0 |
| [Zimbra](http://www.zimbra.com/) 5.0.5 | Yes | Yes | Yes | Cached | No | 8/34 | 50/328 | 2/33 |
| [MS Exchange](http://www.microsoft.com/exchange/default.mspx) | No | Unreliable | ? | No | No | 16/40 | 52/287 | 0/0 |
| [Citadel](http://www.citadel.org/) 7.36 | No | Unreliable | Yes | Yes | Session (flag changes are never seen by other sessions) | 19/34 | 98/328 | 0/0 |
| [hMailServer](http://www.hmailserver.com/) 5.3.3 b1879 | ? | ? | ? | ? | ? | Fails hardcoded OK response format test. Other tests don't work, if OK response test fails. | | |

### Major Problems with Multiple Connections

Makes further testing difficult and **MAY CAUSE ACCIDENTAL MAIL LOSS!**

| Server | Checkpoint | \Recent | Atomic flags | Expunge fetch | Expunge store | Failure groups | Base fails | Ext fails |
| ------ | ---------- | ------- | ------------ | ------------- | ------------- | -------------- | ---------- | --------- |
| [dbmail](http://www.dbmail.org/) 3.0.2 | ? | Unreliable | ? | Yes | Yes |  9/361 - UID/sequence mapping becomes wrong |
| [IBM Domino](http://www.ibm.com/software/lotus/products/notes/) 8.0 | No | Unreliable | ? | ? | No | 16/34 - Too many EXPUNGEs are sent, EXISTS is dropped before sending EXPUNGEs, FETCHing with valid messagesets produce errors |
| [Kerio Mail Server](http://www.kerio.eu/kms_home.html) 6.5.1 | ? | ? | ? | ? | ? | 18/34 - EXPUNGEs are sent wrong |
| [Axigen](http://www.axigen.com/) 7.1.2 | ? | Unreliable | Yes | Broken | Broken | 19/312 - FETCH/STORE sends EXPUNGEs immediately |
:::
