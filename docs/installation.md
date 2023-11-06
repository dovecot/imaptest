---
layout: doc
---

# ImapTest Installation

## Compiling

### Dovecot CE

Download and compile [Dovecot CE sources](https://github.com/dovecot/core/). Use the most recent version possible (current `main` branch is the best).

Two options:
* `git` clone the repository
* Download [ZIP file of main branch](https://github.com/dovecot/core/archive/refs/heads/main.zip)

::: info
ImapTest uses Dovecot's library functions.

Dovecot doesn't have any external dependencies.
:::

1. If using `main` branch, run `autogen.sh`.
1. Compiling goes the usual way: `./configure && make`.
   * There's no need for `make install`.
   * ImapTest configure wants to find `dovecot-config`, which is created by running (and finishing) `make`.
   * If you want to avoid having to install shared Dovecot libraries, you can use `./configure --without-shared-libs`.

### ImapTest

Download and compile [ImapTest](https://github.com/dovecot/imaptest/).

Two options:
* `git` clone the repository
* Download [ZIP file of main branch](https://github.com/dovecot/imaptest/archive/refs/heads/main.zip)

1. Run `autogen.sh`.
1. `./configure --with-dovecot=../dovecot-nightly-compile-directory && make`
   * `--with-dovecot=<path>` parameter is used to specify path to Dovecot CE source's root directory.
1. Either `make install` or run `src/imaptest` directly.

::: tip
You may want to modify the default configuration from `#defines` in `src/settings.h`.

This isn't required, but if you run imaptest often, this way you don't have to give the same parameters every time.
:::
