## Process this file with automake to produce Makefile.in
DEFS = @DEFS@ 

include ${top_srcdir}/modules/common/Modules.inc

EXTRA_DIST = twofish.h

pkglib_LTLIBRARIES = @INSTALL_SECRETKEY_BLOCK_MODULES@

EXTRA_LTLIBRARIES = libtwofish.la

noinst_LTLIBRARIES = @NOINSTALL_SECRETKEY_BLOCK_MODULES@

libtwofish_la_SOURCES = twofish.c
