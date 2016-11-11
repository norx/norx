#!/bin/bash
#
# Script to wrap up implementations for SUPERCOP
#

DEST=crypto_aead
VER=v3

if [ -d "$DEST" ]; then rm -rf $DEST; fi
mkdir -p $DEST

# copy stuff
for DIR in ../norx{3241,3261,6441,6444,6461}; do
  SRC=$DIR
  BASE=$(basename $DIR)
  rsync -a $SRC $DEST --exclude={makefile,kat.h}
  mv $DEST/$BASE $DEST/$BASE$VER
done;

# pack stuff
tar -czf $DEST.tar.gz $DEST
