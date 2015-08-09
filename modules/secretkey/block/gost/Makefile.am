## Process this file with automake to produce Makefile.in
DEFS = @DEFS@ 

include ${top_srcdir}/modules/common/Modules.inc

EXTRA_DIST = gost.h

pkglib_LTLIBRARIES = @INSTALL_SECRETKEY_BLOCK_MODULES@

EXTRA_LTLIBRARIES = libgost.la
		libtripledes.la

noinst_LTLIBRARIES = @NOINSTALL_SECRETKEY_BLOCK_MODULES@
libgost_la_SOURCES = gost.c
libgost_la_LDFLAGS =  $(module_ldflags)
