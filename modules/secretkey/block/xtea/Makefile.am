## Process this file with automake to produce Makefile.in
DEFS = @DEFS@ 

include ${top_srcdir}/modules/common/Modules.inc

EXTRA_DIST = xtea.h

pkglib_LTLIBRARIES = @INSTALL_SECRETKEY_BLOCK_MODULES@

EXTRA_LTLIBRARIES = libxtea.la

noinst_LTLIBRARIES = @NOINSTALL_SECRETKEY_BLOCK_MODULES@
libxtea_la_SOURCES = xtea.c
libxtea_la_LDFLAGS = $(module_ldflags)
