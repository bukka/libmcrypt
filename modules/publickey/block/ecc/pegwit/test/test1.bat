@echo off
  set prompt=$T$G
  echo on

@if exist pegwit.pkr goto :err

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

@echo ---making key
pegwit32 -I "hello there" <test.pri
@echo ---making key 2
pegwit32 -I 1234 <1234.pri
@echo ---encrypting to 2 keys (binary output)
pegwit32 -e1 <test.jnk =hello =1234 test.txt test_e2.bin
@echo ---decrypting with 1st key
pegwit32 -d <test.pri test_e2.bin con
@echo ---decrypting with 2nd key
pegwit32 -d1 <1234.pri test_e2.bin con
@echo ---encrypting to 2 keys (binary output)
pegwit32 -e1 <test.jnk #0 #1 test.txt test_e2.bin
@echo ---decrypting with 1st key
pegwit32 -d <test.pri test_e2.bin con
@echo ---decrypting with 2nd key
pegwit32 -d1 <1234.pri test_e2.bin con
@echo ---verifing (detached)
pegwit32 -v =hello test.txt <test_det.sig
@echo ---verifing (detached)
pegwit32 -v #0 test.txt <test_det.sig

@echo ---listing keys
pegwit32 -l

@pause
@goto :end

:err
@echo error - file pegwit.pkr already exists
@echo can test without deleting this file

:end
