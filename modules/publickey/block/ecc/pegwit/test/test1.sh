#! /bin/sh

if [ -f pegwit.pkr ]
then
  echo "error - file pegwit.pkr already exists"
  echo "can test without deleting this file"
  exit 0
fi

echo "---making key"
../pegwit -i <test.pri >test.pub
echo "---encrypting (binary output)"
../pegwit -e <test.jnk test.pub test.txt test_enc.bin
echo "---decrypting (binary output)"
../pegwit -d <test.pri test_enc.bin /dev/tty
echo "---signing (detached)"
../pegwit -s <test.pri test.txt >test_det.sig
echo "---verifing (detached)"
../pegwit -v test.pub test.txt <test_det.sig

echo "---making key"
../pegwit -I "hello there" <test.pri
echo "---making key 2"
../pegwit -I 1234 <1234.pri
echo "---encrypting to 2 keys (binary output)"
../pegwit -e1 <test.jnk =hello =1234 test.txt test_e2.bin
echo "---decrypting with 1st key"
../pegwit -d <test.pri test_e2.bin /dev/tty
echo "---decrypting with 2nd key"
../pegwit -d1 <1234.pri test_e2.bin /dev/tty
echo "---encrypting to 2 keys (binary output)"
../pegwit "-e1 <test.jnk \#0 \#1 test.txt test_e2.bin"
echo "---decrypting with 1st key"
../pegwit -d <test.pri test_e2.bin /dev/tty
echo "---decrypting with 2nd key"
../pegwit -d1 <1234.pri test_e2.bin /dev/tty
echo "---verifing (detached)"
../pegwit -v =hello test.txt <test_det.sig
echo "---verifing (detached)"
../pegwit "-v \#0 test.txt <test_det.sig"

echo "---listing keys"
../pegwit -l
