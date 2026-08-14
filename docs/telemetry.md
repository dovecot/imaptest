# Telemetry & Structured Data Export

ImapTest emits structured telemetry events internally during test execution.
These events are collected by registered exporter drivers, which handle
serialization and output to external destinations.

## Events

These are the internal events fired within the code. They contain the field
information provided below. The examples shown in the JSON Lines section are
specific to that output format.

### `client_connected`

Fired when a new client establishes a connection.

| Field | Type | Description |
| ----- | ---- | ----------- |
| `event` | String | `client_connected` |
| `ts` | Number | Epoch timestamp (formatted as `seconds.microseconds`) |
| `client_id` | Number | Unique client connection sequence ID |
| `username` | String | Target user login template |
| `protocol` | String | `IMAP` or `POP3` |
| `port` | Number | Remote port connected to |

### `client_disconnected`

Fired when a client session terminates.

| Field | Type | Description |
| ----- | ---- | ----------- |
| `event` | String | `client_disconnected` |
| `ts` | Number | Epoch timestamp (formatted as `seconds.microseconds`) |
| `client_id` | Number | Connection ID |
| `username` | String | Logged username |
| `reason` | String | Disconnect reason (e.g. `Logout`, or socket error details) |
| `duration_usecs` | Number | Total connection duration in microseconds |

### `cmd_completed`

Fired whenever an individual IMAP or POP3 command completes.

| Field | Type | Description |
| ----- | ---- | ----------- |
| `event` | String | `cmd_completed` |
| `ts` | Number | Epoch timestamp (formatted as `seconds.microseconds`) |
| `client_id` | Number | Connection ID |
| `username` | String | Logged username |
| `protocol` | String | `IMAP` or `POP3` |
| `state` | String | Command state name (e.g. `FETCH`, `STORE`, `RETR`) |
| `reply` | String | Response status (`OK`, `NO`, `BAD`, `ERR`). IMAP emits raw `tag_status` (`OK`, `NO`, `BAD`); POP3 emits `OK` for success and `ERR` for failures |
| `duration_usecs` | Number | Command execution latency in microseconds |
| `mailbox` | String | (IMAP only) Current active mailbox name |
| `tag` | Number | (IMAP only) IMAP command tag sequence number |

### `interval_stats`

Fired periodically (every 1 second) to report aggregated performance metrics.

| Field | Type | Description |
| ----- | ---- | ----------- |
| `event` | String | `interval_stats` |
| `ts` | Number | Epoch timestamp (formatted as `seconds.microseconds`) |
| `active_clients` | Number | Connected clients actively processing commands |
| `total_clients` | Number | Total currently connected clients |
| `stalled_count` | Number | Count of clients flagged as stalled |
| `total_disconnects` | Number | Cumulative number of disconnections since startup |
| `<state_name>_count` | Number | Count of executions for that state in the last second |
| `<state_name>_avg_msecs` | Number | Average latency (in ms) for that state in the last second |

### `test_result`

Fired when a scripted test group finishes (only active when using `test=`).

| Field | Type | Description |
| ----- | ---- | ----------- |
| `event` | String | `test_result` |
| `ts` | Number | Epoch timestamp (formatted as `seconds.microseconds`) |
| `test_name` | String | Name of the executed scripted test |
| `passed` | Boolean | Boolean status |
| `skipped` | Boolean | Boolean status (e.g. missing capabilities) |
| `failure_reason` | String | Details of validation/command failure |

### `test_summary`

Fired at the end of all scripted tests execution.

| Field | Type | Description |
| ----- | ---- | ----------- |
| `event` | String | `test_summary` |
| `ts` | Number | Epoch timestamp (formatted as `seconds.microseconds`) |
| `total_groups` | Number | Total executed test groups |
| `group_failures` | Number | Failed test groups count |
| `group_skips` | Number | Skipped test groups count |
| `base_failures` | Number | Individual commands failed in base protocol |
| `base_tests` | Number | Total base protocol commands run |
| `ext_failures` | Number | Individual commands failed in extensions |
| `ext_tests` | Number | Total extension commands run |

### `client_stalled`

Fired when a client has been stalled beyond a threshold (default 15 seconds).

| Field | Type | Description |
| ----- | ---- | ----------- |
| `event` | String | `client_stalled` |
| `ts` | Number | Epoch timestamp (formatted as `seconds.microseconds`) |
| `client_id` | Number | Connection ID |
| `username` | String | Logged username |
| `stalled_secs` | Number | Number of seconds client has been stalled |
| `state` | String | State client is stuck in |

### `checkpoint_error`

Fired when a validation error is encountered during checks (only when using `checkpoint=`).

| Field | Type | Description |
| ----- | ---- | ----------- |
| `event` | String | `checkpoint_error` |
| `ts` | Number | Epoch timestamp (formatted as `seconds.microseconds`) |
| `client_id` | Number | Connection ID |
| `username` | String | Logged username |
| `mailbox` | String | Active mailbox |
| `detail` | String | Details of the checkpoint mismatch |

## Exporter Configuration

Telemetry is enabled using the [`exporter`](/configuration#exporter)
parameter with the format `driver:options`:

```
./imaptest exporter=jsonl:path=/tmp/events.jsonl host=...
```

Each exporter driver receives the same internal event stream but is responsible
for its own serialization format and output destination. The `driver` selects
the exporter implementation; `options` are driver-specific configuration.

## Exporter Drivers

### JSON Lines

The `jsonl` driver writes one JSON object per line to a file or standard output.

**Output path** — provide `path=/path/to/file` or a bare path as options:

```
./imaptest exporter=jsonl:path=/tmp/events.jsonl host=...
./imaptest exporter=jsonl:/tmp/events.jsonl host=...
```

#### Parsing Examples

The JSON Lines format is easy to query with standard tools like `jq`.

* **Filter command completion latencies**:

  ```bash
  tail -f events.jsonl | jq 'select(.event == "cmd_completed") | {state, duration_ms: (.duration_usecs / 1000), reply}'
  ```

* **Detect client connection drops**:

  ```bash
  grep '"event":"client_disconnected"' events.jsonl | jq '{client_id, username, reason}'
  ```

* **Verify test failures in CI**:

  ```bash
  jq 'select(.event == "test_summary") | .group_failures' events.jsonl
  ```

