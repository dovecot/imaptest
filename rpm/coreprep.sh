#!/bin/sh

cd core

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

cd doc/wiki
cp -f Makefile.am.in Makefile.am
echo *.txt | sed 's, , \\/	,g' | tr '/' '\n' >> Makefile.am
cd ../..

cd core/src/lib
test -f $@ || wget -O UnicodeData.txt https://dovecot.org/res/UnicodeData.txt
cd ../../..

cd core/src/lib-fts
test -f WordBreakProperty.txt || wget -O WordBreakProperty.txt https://dovecot.org/res/WordBreakProperty.txt
test -f PropList.txt || wget -O PropList.txt https://dovecot.org/res/PropList.txt

cd ../../..

