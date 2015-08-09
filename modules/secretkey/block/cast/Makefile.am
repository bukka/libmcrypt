## Process this file with automake to produce Makefile.in
DEFS = @DEFS@ 

include ${top_srcdir}/modules/common/Modules.inc

EXTRA_DIST = cast-128.h cast-128_sboxes.h cast-256.h

pkglib_LTLIBRARIES = @INSTALL_SECRETKEY_BLOCK_MODULES@

EXTRA_LTLIBRARIES = libcast-128.la libcast-256.la

noinst_LTLIBRARIES = @NOINSTALL_SECRETKEY_BLOCK_MODULES@
libcast_256_la_SOURCES = cast-256.c
libcast_256_la_LDFLAGS = $(module_ldflags)
libcast_128_la_SOURCES = cast-128.c
libcast_128_la_LDFLAGS = $(module_ldflags)
