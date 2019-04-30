#!/bin/sh

mkdir -p coreprep/doc/wiki
cd coreprep
if test ! -f doc/wiki/Authentication.txt; then
  cd doc
  wget https://www.dovecot.org/tmp/wiki2-export.tar.gz
  tar xzf wiki2-export.tar.gz
  if [ $? != 0 ]; then
    echo "Failed to uncompress wiki docs"
    exit
  fi
  mv wiki2-export/*.txt wiki/
  rm -rf wiki2-export wiki2-export.tar.gz
  cd ..
fi

cd ..

mkdir -p coreprep/src/lib
test -f coreprep/src/lib/UnicodeData.txt || wget -O coreprep/src/lib/UnicodeData.txt https://dovecot.org/res/UnicodeData.txt

mkdir -p coreprep/src/lib-fts
test -f coreprep/src/lib-fts/WordBreakProperty.txt || wget -O coreprep/src/lib-fts/WordBreakProperty.txt https://dovecot.org/res/WordBreakProperty.txt
test -f coreprep/src/lib-fts/PropList.txt || wget -O coreprep/src/lib-fts/PropList.txt https://dovecot.org/res/PropList.txt

