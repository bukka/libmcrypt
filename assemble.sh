#!/bin/sh

cat output-starting.src > lastline.src

MODULES=`cat output-starting.src`

for i in secretkey publickey
do
  for j in block stream
  do
    for k in `cat modules/$i/$j/list.txt`
    do
      MODULES="$MODULES modules/$i/$j/$k/Makefile"
    done
  done
done 


MODULES="$MODULES `cat output-ending.src`"

echo $MODULES

cat configure.in.src > configure.in

echo $MODULES >> configure.in

