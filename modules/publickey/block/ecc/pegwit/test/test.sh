#! /bin/sh

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
echo "---clearsigning"
../pegwit -S test.txt <test.pri >test_sig.txt
echo "---clearverifing"
../pegwit -V test.pub test_sig.txt
echo "---encrypting conventionaly (binary output)"
../pegwit -E <test.pri test.txt test_cnv.bin
echo "---decrypting conventionaly (binary output)"
../pegwit -D <test.pri test_cnv.bin /dev/tty

echo "---encrypting (text output)"
../pegwit -fe test.pub test.jnk <test.txt >test_enc.txt
echo "---decrypting (text output)"
../pegwit -fd test.pri <test_enc.txt
echo "---encrypting conventionaly (text output)"
../pegwit -fE test.pri <test.txt >test_cnv.txt
echo "---decrypting conventionaly (text output)"
../pegwit -fD test.pri <test_cnv.txt
echo "---clearsigning"
../pegwit -fS test.pri <test.txt >test_sg2.txt
echo "---clearverifing"
../pegwit -fV test.pub <test_sg2.txt

echo "---making key 2"
../pegwit -i <1234.pri >1234.pub
echo "---encrypting to 2 keys (binary output)"
../pegwit -e1 <test.jnk test.pub 1234.pub test.txt test_e2.bin
echo "---decrypting with 1st key"
../pegwit -d <test.pri test_e2.bin /dev/tty
echo "---decrypting with 2nd key"
../pegwit -d1 <1234.pri test_e2.bin /dev/tty
echo "---encrypting to 2 keys (text output)"
../pegwit -fe1 test.pub 1234.pub test.jnk <test.txt >test_e2.txt
echo "---decrypting with 1st key"
../pegwit -fd test.pri <test_e2.txt
echo "---decrypting with 2nd key"
../pegwit -fd1 1234.pri <test_e2.txt
