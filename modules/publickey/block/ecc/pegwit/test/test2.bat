@echo off

pegwit32 -E <test.pri  1.txt  1.enc
pegwit32 -E <test.pri  6.txt  6.enc
pegwit32 -E <test.pri  7.txt  7.enc
pegwit32 -E <test.pri  8.txt  8.enc
pegwit32 -E <test.pri  9.txt  9.enc
pegwit32 -E <test.pri 17.txt 17.enc
pegwit32 -E <test.pri 18.txt 18.enc
pegwit32 -E <test.pri 10.txt 10.enc
pegwit32 -E <test.pri 14.txt 14.enc
pegwit32 -E <test.pri 15.txt 15.enc
pegwit32 -E <test.pri 16.txt 16.enc
pegwit32 -E <test.pri 30.txt 30.enc
pegwit32 -E <test.pri 31.txt 31.enc
pegwit32 -E <test.pri 32.txt 32.enc
pegwit32 -E <test.pri 33.txt 33.enc

pegwit32 -E <test.pri 4095.txt 4095.enc
pegwit32 -E <test.pri 4096.txt 4096.enc
pegwit32 -E <test.pri 4097.txt 4097.enc
pegwit32 -E <test.pri 4098.txt 4098.enc
pegwit32 -E <test.pri 4102.txt 4102.enc
pegwit32 -E <test.pri 4103.txt 4103.enc
pegwit32 -E <test.pri 4104.txt 4104.enc
pegwit32 -E <test.pri 4105.txt 4105.enc
pegwit32 -E <test.pri 4106.txt 4106.enc
pegwit32 -E <test.pri 4110.txt 4110.enc
pegwit32 -E <test.pri 4111.txt 4111.enc
pegwit32 -E <test.pri 4112.txt 4112.enc
pegwit32 -E <test.pri 4113.txt 4113.enc
pegwit32 -E <test.pri 4114.txt 4114.enc

pegwit32 -D <test.pri  1.enc  1.dec
pegwit32 -D <test.pri  6.enc  6.dec
pegwit32 -D <test.pri  7.enc  7.dec
pegwit32 -D <test.pri  8.enc  8.dec
pegwit32 -D <test.pri  9.enc  9.dec
pegwit32 -D <test.pri 17.enc 17.dec
pegwit32 -D <test.pri 18.enc 18.dec
pegwit32 -D <test.pri 10.enc 10.dec
pegwit32 -D <test.pri 14.enc 14.dec
pegwit32 -D <test.pri 15.enc 15.dec
pegwit32 -D <test.pri 16.enc 16.dec
pegwit32 -D <test.pri 30.enc 30.dec
pegwit32 -D <test.pri 31.enc 31.dec
pegwit32 -D <test.pri 32.enc 32.dec
pegwit32 -D <test.pri 33.enc 33.dec

pegwit32 -D <test.pri 4095.enc 4095.dec
pegwit32 -D <test.pri 4096.enc 4096.dec
pegwit32 -D <test.pri 4097.enc 4097.dec
pegwit32 -D <test.pri 4098.enc 4098.dec
pegwit32 -D <test.pri 4102.enc 4102.dec
pegwit32 -D <test.pri 4103.enc 4103.dec
pegwit32 -D <test.pri 4104.enc 4104.dec
pegwit32 -D <test.pri 4105.enc 4105.dec
pegwit32 -D <test.pri 4106.enc 4106.dec
pegwit32 -D <test.pri 4110.enc 4110.dec
pegwit32 -D <test.pri 4111.enc 4111.dec
pegwit32 -D <test.pri 4112.enc 4112.dec
pegwit32 -D <test.pri 4113.enc 4113.dec
pegwit32 -D <test.pri 4114.enc 4114.dec

pause
