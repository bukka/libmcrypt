## Process this file with automake to produce Makefile.in
DEFS = @DEFS@ 

include ${top_srcdir}/common/Modules.inc

EXTRA_DIST = rijndael.h

pkglib_LTLIBRARIES = @INSTALL_SECRETKEY_BLOCK_MODULES@

EXTRA_LTLIBRARIES = librijndael-128.la librijndael-192.la librijndael-256.la

noinst_LTLIBRARIES = @NOINSTALL_SECRETKEY_BLOCK_MODULES@

librijndael_128_la_SOURCES = rijndael-128.c
librijndael_128_la_LDFLAGS = $(module_ldflags)
librijndael_192_la_SOURCES = rijndael-192.c
librijndael_192_la_LDFLAGS = $(module_ldflags)
librijndael_256_la_SOURCES = rijndael-256.c
librijndael_256_la_LDFLAGS = $(module_ldflags)
