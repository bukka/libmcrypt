LIBS	= 
CC	= gcc
CFLAGS	= -g -O2
LDFLAGS	= 
LEX	= flex
LEXLIB	= -lfl
DEFS	= -DLITTLE_ENDIAN -UBIG_ENDIAN -D_ENDIAN_H
LN	= ln -s
RM	= rm -f

OBJECTS = lip.o binascw.o rijndael-alg-fst.o eliptic.o protocols1.o\
	pegwit.o pegwitw.o pgwecc.o onb_integer.o onb.o sha256.o keyring.o

SOURCES = lip.c binascw.c rijndael-alg-fst.c eliptic.c protocols1.o\
	pegwit.c pegwitw.c pgwecc.c onb_integer.c onb.c sha256.c keyring.c

INCLUDES = -I./

default: pegwit

all: pegwit

.c.o:
	$(CC) $(CFLAGS) $(DEFS) $(PP_DEFS) $(INCLUDES) -c $<

pegwit: $(OBJECTS)
	$(CC) $(CFLAGS) $(LDFLAGS) $(DEFS) -o pegwit $(OBJECTS) $(LIBS)
clean:
	$(RM) $(OBJECTS)

install: pegwit
	strip pegwit

# dependencies

lip.o : lip.c lip.h
sha256.o : sha256.c sha256.h
binasc.o : binascw.c binascw.h pegwitw.h
eliptic.o : eliptic.c field2n.h eliptic.h
pegwit.o : pegwit.c binascw.h pegwitw.h keyring.h
pegwitw.o : pegwitw.c binascw.h pegwitw.h keyring.h rijndael-alg-fst.h sha256.h \
	pgwecc.h field2n.h eliptic.h protocols.h
pgwecc.o : pgwecc.c pgwecc.h field2n.h eliptic.h lip.h protocols.h
protocols1.o : protocols1.c field2n.h eliptic.h protocols.h
onb_integer.o : onb_integer.c field2n.h eliptic.h lip.h protocols.h sha256.h
onb.o : onb.c field2n.h
rijndael-alg-fst.o : rijndael-alg-fst.c rijndael-alg-fst.h
keyring.o : keyring.c keyring.h
