## Process this file with automake to produce Makefile.in
DEFS = @DEFS@ 

include ../common/Modules.inc

EXTRA_DIST = twofish.h saferplus.h rijndael.h \
		rc2.h serpent.h cast-256.h blowfish.h \
		cast-128.h cast-128_sboxes.h des.h tripledes.h \
		3-way.h safer.h xtea.h

pkglib_LTLIBRARIES = @INSTALL_SECRETKEY_BLOCK_MODULES@

EXTRA_LTLIBRARIES = twofish.la rijndael-128.la \
		rijndael-192.la rijndael-256.la saferplus.la rc2.la xtea.la \
		serpent.la safer-sk64.la safer-sk128.la cast-256.la loki97.la \
		gost.la threeway.la cast-128.la blowfish.la des.la blowfish-compat.la \
		tripledes.la

noinst_LTLIBRARIES = @NOINSTALL_SECRETKEY_BLOCK_MODULES@

twofish_la_SOURCES = twofish.c
twofish_la_LDFLAGS =  $(module_ldflags)
rijndael_128_la_SOURCES = rijndael-128.c
rijndael_128_la_LDFLAGS = $(module_ldflags)
rijndael_192_la_SOURCES = rijndael-192.c
rijndael_192_la_LDFLAGS = $(module_ldflags)
rijndael_256_la_SOURCES = rijndael-256.c
rijndael_256_la_LDFLAGS = $(module_ldflags)
saferplus_la_SOURCES = saferplus.c
saferplus_la_LDFLAGS = $(module_ldflags)
serpent_la_SOURCES = serpent.c
serpent_la_LDFLAGS = $(module_ldflags)
xtea_la_SOURCES = xtea.c
xtea_la_LDFLAGS = $(module_ldflags)
rc2_la_SOURCES = rc2.c
rc2_la_LDFLAGS =  $(module_ldflags)
safer_sk64_la_SOURCES = safer64.c
safer_sk64_la_LDFLAGS = $(module_ldflags)
safer_sk128_la_SOURCES = safer128.c
safer_sk128_la_LDFLAGS = $(module_ldflags)
cast_256_la_SOURCES = cast-256.c
cast_256_la_LDFLAGS = $(module_ldflags)
loki97_la_SOURCES = loki97.c
loki97_la_LDFLAGS = $(module_ldflags)
gost_la_SOURCES = gost.c
gost_la_LDFLAGS =  $(module_ldflags)
threeway_la_SOURCES = 3-way.c
threeway_la_LDFLAGS = $(module_ldflags)
blowfish_la_SOURCES = blowfish.c
blowfish_la_LDFLAGS = $(module_ldflags)
blowfish_compat_la_SOURCES = blowfish-compat.c
blowfish_compat_la_LDFLAGS = $(module_ldflags)
cast_128_la_SOURCES = cast-128.c
cast_128_la_LDFLAGS = $(module_ldflags)
des_la_SOURCES = des.c
des_la_LDFLAGS = $(module_ldflags)
tripledes_la_SOURCES = tripledes.c
tripledes_la_LDFLAGS = $(module_ldflags)
