## Process this file with automake to produce Makefile.in
DEFS = @DEFS@ 

include ../common/Modules.inc

EXTRA_DIST = safer.h saferplus.h

pkglib_LTLIBRARIES = @INSTALL_SECRETKEY_BLOCK_MODULES@

EXTRA_LTLIBRARIES = safer-sk64.la safer-sk128.la saferplus.la


noinst_LTLIBRARIES = @NOINSTALL_SECRETKEY_BLOCK_MODULES@
rijndael_256_la_LDFLAGS = $(module_ldflags)
saferplus_la_SOURCES = saferplus.c
safer_sk64_la_SOURCES = safer64.c
safer_sk64_la_LDFLAGS = $(module_ldflags)
safer_sk128_la_SOURCES = safer128.c
safer_sk128_la_LDFLAGS = $(module_ldflags)
