---
layout: doc
---

# ImapTest Examples

## Command Examples

### Basic Operation

```
imaptest host=127.0.0.1 port=143 user=testuser pass=testpass mbox=dovecot.mbox
```

### Test IMAP Server Compliancy

```
imaptest checkpoint=1
imaptest checkpoint=1 logout=0 expunge=10
imaptest checkpoint=1 rawlog no_pipelining
imaptest own_msgs expunge=5 logout=1
imaptest own_flags expunge=5 logout=1
imaptest logout=0 search=100 expunge=10 clients=1
```

### Benchmarking

If you want to do benchmarking, you can set it to run for specified amount of time, and you should also give random number generator the same seed every time:

```
imaptest seed=123 secs=300
```

If you want to test/benchmark only the login+logout speed, use:

```
imaptest - select=0
```

To create a lot of long-running clients doing STATUS and NOOPs:

```
imaptest clients=100 - logout=0 status=50 noop=50 delay=100
```

Benchmarking how fast messages can be saved:

```
imaptest - append=100,0 logout=0 msgs=10000000
```

### Functional Testing

To test copying messages:

```
imaptest copybox=Trash
```

By default LOGIN command is used. If you want to try "AUTHENTICATE PLAIN":

```
imaptest auth=100
```

If you want to use "AUTHENTICATE SCRAM-SHA-1"

```
imaptest mech=scram-sha-1
```

### Scripted Test

Run [scripted tests](/scripted_test) from a given directory:

```
imaptest test=tests rawlog
```

## Execution Example

First, you need to make sure that you have high enough open file limit for the
user running imaptest by doing something like: `ulimit -n 65535` (this might
also require editing `nofile` in `/etc/security/limits.conf` accordingly).

For very intense load testing it's also possible to run out of TCP sockets so
setting `sysctl -w net.ipv4.tcp_tw_reuse=1` helps.

### Example Session

An example session, using [profiles](/profile):

```
imaptest pass=testpass host=127.0.0.1 mbox=testmbox profile=profile.conf clients=100 [no_pipelining] [secs=30]
```

#### Parameters Used

| Parameter      | Description                             |
| -------------- | --------------------------------------- |
| `pass`         | All users should have the same password |
| `host`         | Host to connect to                      |
| `mbox`         | \<CR\>\<LF\> terminated mbox format file to use for source emails |
| `profile`      | Profile configuration file              |
| `clients`      | Number of concurrent clients            |
| `no_pipelining`| (**OPTIONAL**) For IMAP testing, this can be specified to only send a single IMAP command at a time and wait for a response before sending the next one. This should be used to get accurate IMAP latencies. |
| `secs` | (**OPTIONAL**) Number of seconds to run the test. If not specified, the process must be ended manually either with Ctrl+c (if there are stuck connections and you want to force it to end, use ctrl+c twice) or killing the process directly. |

#### Output

```
$ ./imaptest pass=testpass host=127.0.0.1 mbox=testmbox profile=pop3-profile.conf clients=100 secs=20

Logi List Stat Sele Fetc Fet2 Stor Dele Expu Appe Logo LMTP

 99    0    0   99    0  191    0    0  191    0   99   99   0/  0 [99%]

Warning: LMTP: Reached 175 connections, throttling

 107   0    0  107    0  261    0    0  254    0  107  276   0/  0
 103   0    0  103    0  243    0    0  243    0  103  336   0/  0
 103   0    0  103    0   78    0    0   78    0  103  348   0/  0
 108   0    0  108    0    0    0    0    0    0  108  266   3/  3
 1     0    0   1     0    0    0    0    0    0    1  261   0/  0
 0     0    0   0     0    0    0    0    0    0    0  347   0/  0
 99    0    0   99    0  911    0    0  911    0   91  191   8/  8
 96    0    0   92    0  357    0    0  347    0   10  274  94/ 94
 135   0    0  138    0  616    0    0  613    0  132  387  97/ 97
 30    0    0   23    0   38    0    0    6    0   0  159 ms/cmd avg

Logi List Stat Sele Fetc Fet2 Stor Dele Expu Appe Logo LMTP

 68    0    0   69    0  319    0    0  332    0  165  269   0/100
 100   0    0  100    0    1    0    0    1    0  100  350   0/  0
 1     0    0    1    0    0    0    0    0    0    1  350   0/  0
 91    0    0   86    0  662    0    0  662    0   68  185  91/ 91
 8     0    0   13    0  217    0    0  217    0   31  375   0/  0
 100   0    0   57    0    0    0    0    0    0    2  260 100/100
 16    0    0   59    0  578    0    0  578    0  114  265   0/100
 183   0    0  183    0  637    0    0  637    0  183  350   0/  0
 101   0    0  101    0   54    0    0   54    0  101  350   0/  0
 24    0    0   25    0   16    0    0    1    0    0  125 ms/cmd avg 

Totals:

Logi List Stat Sele Fetc Fet2 Stor Dele Expu Appe Logo LMTP
1519    0    0 1519    0 5125    0    0 5118    0 1519 5714
```

The warning can be ignored because we are intentionally throttling the number
of LMTP connections in this configuration.

There is a line of output every second that is showing the number of commands
sent per command. See [states](/states) for an explanation of each column.

Every 10 seconds a line is output showing average duration per connection.
This is the most important one to watch; if the ms/cmd starts increasing then
this indicates an issue with the platform. If everything is operating normally
it should remain approximately the same for all commands.

At exit, the total number of operations performed during the test is output.
