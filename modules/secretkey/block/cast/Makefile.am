## Process this file with automake to produce Makefile.in
DEFS = @DEFS@ 

include ${top_srcdir}/modules/common/Modules.inc

EXTRA_DIST = cast-128.h cast-128_sboxes.h cast-256.h

pkglib_LTLIBRARIES = @INSTALL_SECRETKEY_BLOCK_MODULES@

EXTRA_LTLIBRARIES = cast-128.la cast-256.la
		tripledes.la

noinst_LTLIBRARIES = @NOINSTALL_SECRETKEY_BLOCK_MODULES@
cast_256_la_SOURCES = cast-256.c
cast_256_la_LDFLAGS = $(module_ldflags)
cast_128_la_SOURCES = cast-128.c
cast_128_la_LDFLAGS = $(module_ldflags)
