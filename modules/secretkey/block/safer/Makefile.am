## Process this file with automake to produce Makefile.in
DEFS = @DEFS@ 

include ${top_srcdir}/modules/common/Modules.inc

EXTRA_DIST = safer.h saferplus.h

pkglib_LTLIBRARIES = @INSTALL_SECRETKEY_BLOCK_MODULES@

EXTRA_LTLIBRARIES = libsafer-sk64.la libsafer-sk128.la libsaferplus.la


noinst_LTLIBRARIES = @NOINSTALL_SECRETKEY_BLOCK_MODULES@
libsaferplus_la_SOURCES = saferplus.c
libsafer_sk64_la_SOURCES = safer64.c
libsafer_sk64_la_LDFLAGS = $(module_ldflags)
libsafer_sk128_la_SOURCES = safer128.c
libsafer_sk128_la_LDFLAGS = $(module_ldflags)
