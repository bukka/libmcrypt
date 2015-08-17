#!/bin/sh

cat output-starting.src > lastline.src

#MODULES=`cat output-starting.src`

#for i in secretkey publickey
#do
#  for j in block stream
#  do
#    for k in `cat modules/$i/$j/list.txt`
#    do
#      MODULES="$MODULES modules/$i/$j/$k/Makefile"
#    done
#  done
#done 

# temporary list
MODULES="AC_OUTPUT([Makefile libmcrypt.spec lib/Makefile modules/Makefile \
modules/secretkey/Makefile modules/secretkey/modes/Makefile \
modules/secretkey/modes/cbc/Makefile \
modules/secretkey/block/Makefile \
modules/secretkey/block/3-way/Makefile"

MODULES="$MODULES `cat output-ending.src`"

cat configure.ac.src > configure.ac

echo $MODULES >> configure.ac

