## Process this file with automake to produce Makefile.in
DEFS = @DEFS@ 

include ../common/Modules.inc

EXTRA_DIST = blowfish.h

pkglib_LTLIBRARIES = @INSTALL_SECRETKEY_BLOCK_MODULES@

EXTRA_LTLIBRARIES = blowfish.la
		tripledes.la

noinst_LTLIBRARIES = @NOINSTALL_SECRETKEY_BLOCK_MODULES@
blowfish_la_SOURCES = blowfish.c
blowfish_la_LDFLAGS = $(module_ldflags)
blowfish_compat_la_SOURCES = blowfish-compat.c
blowfish_compat_la_LDFLAGS = $(module_ldflags)
