## Process this file with automake to produce Makefile.in
DEFS = @DEFS@ 

include ../common/Modules.inc

EXTRA_DIST = rijndael.h

pkglib_LTLIBRARIES = @INSTALL_SECRETKEY_BLOCK_MODULES@

EXTRA_LTLIBRARIES = rijndael-128.la rijndael-192.la rijndael-256.la

noinst_LTLIBRARIES = @NOINSTALL_SECRETKEY_BLOCK_MODULES@

rijndael_128_la_SOURCES = rijndael-128.c
rijndael_128_la_LDFLAGS = $(module_ldflags)
rijndael_192_la_SOURCES = rijndael-192.c
rijndael_192_la_LDFLAGS = $(module_ldflags)
rijndael_256_la_SOURCES = rijndael-256.c
rijndael_256_la_LDFLAGS = $(module_ldflags)
