@echo off

@echo ---making key
pegwit32 -i <test.pri >test.pub
@echo ---encrypting (binary output)
pegwit32 -e <test.jnk test.pub test.txt test_enc.bin
@echo ---decrypting (binary output)
pegwit32 -d <test.pri test_enc.bin con
@echo ---signing (detached)
pegwit32 -s <test.pri test.txt >test_det.sig
@echo ---verifing (detached)
pegwit32 -v test.pub test.txt <test_det.sig
@echo ---clearsigning
pegwit32 -S test.txt <test.pri >test_sig.txt
@echo ---clearverifing
pegwit32 -V test.pub test_sig.txt
@echo ---encrypting conventionaly (binary output)
pegwit32 -E <test.pri test.txt test_cnv.bin
@echo ---decrypting conventionaly (binary output)
pegwit32 -D <test.pri test_cnv.bin con

@echo ---encrypting (text output)
pegwit32 -fe test.pub test.jnk <test.txt >test_enc.txt
@echo ---decrypting (text output)
pegwit32 -fd test.pri <test_enc.txt
@echo ---encrypting conventionaly (text output)
pegwit32 -fE test.pri <test.txt >test_cnv.txt
@echo ---decrypting conventionaly (text output)
pegwit32 -fD test.pri <test_cnv.txt
@echo ---clearsigning
pegwit32 -fS test.pri <test.txt >test_sg2.txt
@echo ---clearverifing
pegwit32 -fV test.pub <test_sg2.txt

@echo ---making key 2
pegwit32 -i <1234.pri >1234.pub
@echo ---encrypting to 2 keys (binary output)
pegwit32 -e1 <test.jnk test.pub 1234.pub test.txt test_e2.bin
@echo ---decrypting with 1st key
pegwit32 -d <test.pri test_e2.bin con
@echo ---decrypting with 2nd key
pegwit32 -d1 <1234.pri test_e2.bin con
@echo ---encrypting to 2 keys (text output)
pegwit32 -fe1 test.pub 1234.pub test.jnk <test.txt >test_e2.txt
@echo ---decrypting with 1st key
pegwit32 -fd test.pri <test_e2.txt
@echo ---decrypting with 2nd key
pegwit32 -fd1 1234.pri <test_e2.txt
@pause
