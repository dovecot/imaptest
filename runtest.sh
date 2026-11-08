#!/usr/bin/env bash

fail=0

env USER=testuser1 PATH=$PATH:$PWD/imaptest/src run-parts imaptest/tests || fail=1

if [ $fail != 0 ]; then
  sudo cat /tmp/dovecot.log
  exit 1
fi
