# ImapTest - IMAP Server Tester

ImapTest is a generic IMAP server compliancy tester that works with all IMAP servers. It supports stress testing with state tracking, scripted testing, and benchmarking.

## Project Overview

- **Main Technologies**: C, Autotools (Autoconf, Automake, Libtool).
- **Dependencies**: Depends heavily on Dovecot's internal libraries (`lib-dovecot`).
- **Core Components**:
    - **Main Entry**: `src/imaptest.c` handles initialization and argument parsing.
    - **Protocol Clients**: `src/imap-client.c` and `src/pop3-client.c` implement IMAP and POP3 interactions.
    - **State Management**: `src/mailbox-state.c` and `src/client-state.c` track the expected state of the server.
    - **Scripted Tests**: `src/test-exec.c` and `src/test-parser.c` execute the tests located in `src/tests/`.
    - **Documentation**: A VitePress-based documentation site is located in `docs/`.

## Building and Running

### Build Requirements
You must have the Dovecot source code compiled on your system, as ImapTest uses its library functions.

Dovecot source can be found at https://github.com/dovecot/core/ - the "main" branch should be used with the "main" branch of ImapTest. 

### Build Commands
1. **Generate build files**:
   ```bash
   ./autogen.sh
   ```
2. **Configure**:
   ```bash
   ./configure --with-dovecot=/path/to/dovecot/source
   ```
3. **Compile**:
   ```bash
   make
   ```

### Running ImapTest
ImapTest uses a unique `key=value` format for command-line arguments.

- **Stress Testing**:
  ```bash
  ./src/imaptest host=127.0.0.1 user=testuser pass=testpass
  ```
- **Scripted Testing**:
  ```bash
  ./src/imaptest test=src/tests host=127.0.0.1 user=testuser pass=testpass
  ```

## Testing

### Scripted Tests
The primary testing mechanism is via scripted tests located in `src/tests/`. Each subdirectory contains tests for specific IMAP features (e.g., `append`, `fetch`, `search`).

### Running Tests
You can run the full suite of scripted tests by pointing the `test` parameter to the `src/tests` directory.
```bash
./src/imaptest test=src/tests user=... host=...
```

The `build-aux/run-test.sh` script is also available for running tests, particularly when Valgrind profiling is needed.

## Development Conventions

- **Coding Style**: Follows Dovecot's internal coding style. It uses Dovecot's utility library (`lib.h`, `array.h`, `str.h`, etc.).
- **Configuration**: Default settings are defined in `src/settings.h`.
- **Protocol Compliance**: The tester is designed to verify RFC compliance; new tests should reference relevant IMAP RFCs.
- **Documentation**: Documentation is maintained in Markdown within the `docs/` folder and served via VitePress. Use `npm run docs:dev` to preview changes.
