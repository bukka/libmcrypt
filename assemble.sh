#!/bin/sh
rm -f modules.build
touch modules.build
for i in secretkey publickey
do
  for j in block stream
  do
    cat modules/$i/$j/list.txt >> modules.build
  done
done 

