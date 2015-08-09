## Process this file with automake to produce Makefile.in
DEFS = @DEFS@ 

include ${top_srcdir}/modules/common/Modules.inc

EXTRA_DIST = des.h tripledes.h

pkglib_LTLIBRARIES = @INSTALL_SECRETKEY_BLOCK_MODULES@

EXTRA_LTLIBRARIES = libdes.la libtripledes.la
		libtripledes.la

noinst_LTLIBRARIES = @NOINSTALL_SECRETKEY_BLOCK_MODULES@
libdes_la_SOURCES = des.c
libdes_la_LDFLAGS = $(module_ldflags)
libtripledes_la_SOURCES = tripledes.c
libtripledes_la_LDFLAGS = $(module_ldflags)
