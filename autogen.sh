#!/bin/sh

# If you've non-standard directories, set these
#ACLOCAL_DIR=

if test "$ACLOCAL_DIR" != ""; then
  ACLOCAL="aclocal -I $ACLOCAL_DIR"
  export ACLOCAL
fi

autoreconf -i
