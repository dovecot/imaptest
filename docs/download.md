---
layout: doc
---

# ImapTest Download

## Linux packages

The [Dovecot Team](https://dovecot.org/) creates ImapTest packages for
several different Linux distributions.

Instructions on how to configure your system to install the packages can be
found on the [Dovecot Community Repositories](https://repo.dovecot.org/) page.

## Static Binaries ("latest")

Static binaries are automatically compiled whenever a commit is pushed to
the source repository.

**Download link: https://github.com/dovecot/imaptest/releases/tag/latest**

## Docker Container

ImapTest is available as a Docker container on Docker Hub: [`dovecot/imaptest`](https://hub.docker.com/r/dovecot/imaptest).

To run ImapTest with Docker:

```bash
docker run --rm -it dovecot/imaptest [options]
```

::: info
ImapTest can also be compiled from source. See [build](/build)
for details.
:::
