---
layout: doc
---

# IMAP Server Benchmarking

## Overview

"Which IMAP server is the fastest?" is a difficult question to answer, because the answer completely depends on what IMAP clients are used.

There are basically two types of IMAP clients:

1. Caching IMAP clients which fetch new messages only once from the server. After that the only metadata the client is interested of is the message's flags. Most real IMAP clients belong to this category (e.g. Outlook, Thunderbird, Apple Mail).
1. Non-caching IMAP clients keep fetching the same messages over and over again. Webmails typically belong to this category.

Some IMAP servers cache commonly used metadata for non-caching clients to avoid reading and parsing the message multiple times. This has however some problems:

* If it's done for users who use only caching IMAP clients, it adds extra disk I/O (and consume disk space unneededly).
* What fields should be cached? If too many are cached, it again adds extra unnecessary disk I/O. If too few are cached, all the caching was for nothing because the server has to now parse the message anyway.

If clients can be placed into two categories, servers can be placed into three:

1. Non-caching (or very little / non-permanently caching) servers parse the message whenever a client requests for metadata (e.g. UW-IMAP, Courier).
1. Statically caching servers keep a predefined list of metadata permanently cached (e.g. Cyrus).
1. Dynamically caching servers change the list of permanently cached metadata based on what clients actually use (e.g. Dovecot).

We can describe the client <-> server performance as a table (assumes theoretically optimal implementations):

|                        | **Non-Caching Server** | **Statically Caching Server**   | **Dynamically Caching Server** |
| ---------------------- | ---------------------- | ------------------------------- | ------------------------------ |
| **Caching Client**     | Optimal performance    | Wastes disk I/O and disk space. | Near-optimal performance       |
| **Non-Caching Client** | Worst performance      | Optimal performance if cached fields match exactly the wanted fields. Near-optimal if all fields are cached. Bad performance if some fields are missing | Optimal performance |

So when you read about IMAP benchmarks, make sure you know what caching models the benchmark tests for.

## Other Issues

### Mail Delivery

With caching IMAP servers the metadata caching is often offloaded to MDA. This means that while the mail delivery may be slower than for non-caching IMAP servers, the IMAP performance may be better as a result. Then again if only caching clients are used, the extra disk I/O still slows down the server, even if it was done outside the actual IMAP session.

### Disk I/O

The performance bottleneck with most IMAP servers is disk I/O. The benchmark should reflect that by using realistic amount of disk I/O instead of getting everything cached in memory after running a while.

### fsync()

Some servers call `fsync()` after saving messages and possibly performing some other operations to guarantee (if sysadmin so configured) that changes have been written to disk before replying OK to client.

Other servers don't use `fsync()` at all and some can be configured either way.

Using `fsync()` should guarantee that mails don't get lost when the server unexpectedly dies, but it can make the performance somewhat worse, especially in benchmarks.

### Dynamic Caching

With dynamically caching servers, if the benchmark switches between different client behaviors for the same user the result may be bad, because the server assumes the user is using multiple clients and tries to optimize the performance for all of them.

## Software

* [MStone](http://mstone.sourceforge.net/) - Benchmarks for caching client performance.
* ImapTest - Benchmarks for non-caching client performance.
