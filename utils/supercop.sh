#!/bin/bash
#
# NORX reference source code package - script to wrap up implementations for SUPERCOP
#
# Written in 2014 by Philipp Jovanovic <jovanovic@fim.uni-passau.de>
#
# To the extent possible under law, the author(s) have dedicated all copyright
# and related and neighboring rights to this software to the public domain
# worldwide. This software is distributed without any warranty.
#
# You should have received a copy of the CC0 Public Domain Dedication along with
# this software. If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.

DEST=crypto_aead
VER=v1

if [ -d "$DEST" ]; then rm -rf $DEST; fi
mkdir -p $DEST

for DIR in ../norx*; do
  SRC=$DIR
  BASE=$(basename $DIR)
  rsync -a $SRC $DEST --exclude={makefile,kat.h}
  mv $DEST/$BASE $DEST/$BASE$VER
done;

if [ `uname` == "Darwin" ]; then
  find $DEST -type f -exec sed -i "" -e 's/defined(SUPERCOP)/1/g' '{}' \;
else
  find $DEST -type f -exec sed -i 's/defined(SUPERCOP)/1/g' '{}' \;
fi
