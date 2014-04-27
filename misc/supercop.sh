#!/bin/bash
#
# NORX reference source code package - wrap up reference implementation for SUPERCOP
#
# Written in 2014 by Philipp Jovanovic <jovanovic@fim.uni-passau.de>
#
# To the extent possible under law, the author(s) have dedicated all copyright
# and related and neighboring rights to this software to the public domain
# worldwide. This software is distributed without any warranty.
#
# You should have received a copy of the CC0 Public Domain Dedication along with
# this software. If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.

AEAD=crypto_aead
TYPE=ref
VER=v1

if [ -d "$AEAD" ]; then rm -rf $AEAD; fi

for DIR in ../norx*; do
  SRC=$DIR/$TYPE
  DEST=$AEAD/$(basename $DIR)$VER/$TYPE
  mkdir -p $DEST
  cp $SRC/{api.h,norx*} $DEST
  sed -e 's/defined(SUPERCOP)/1/g' $SRC/caesar.c > $DEST/encrypt.c
done;
tar -czf $AEAD.tar.gz $AEAD
