## Process this file with automake to produce Makefile.in
DEFS = @DEFS@ 

include ${top_srcdir}/modules/common/Modules.inc

EXTRA_DIST = des.h tripledes.h

pkglib_LTLIBRARIES = @INSTALL_SECRETKEY_BLOCK_MODULES@

EXTRA_LTLIBRARIES = des.la tripledes.la
		tripledes.la

noinst_LTLIBRARIES = @NOINSTALL_SECRETKEY_BLOCK_MODULES@
des_la_SOURCES = des.c
des_la_LDFLAGS = $(module_ldflags)
tripledes_la_SOURCES = tripledes.c
tripledes_la_LDFLAGS = $(module_ldflags)
