## Process this file with automake to produce Makefile.in
DEFS = @DEFS@ 

include ${top_srcdir}modules/common/Modules.inc

EXTRA_DIST = rc2.h

pkglib_LTLIBRARIES = @INSTALL_SECRETKEY_BLOCK_MODULES@

EXTRA_LTLIBRARIES = librc2.la

noinst_LTLIBRARIES = @NOINSTALL_SECRETKEY_BLOCK_MODULES@
librc2_la_SOURCES = rc2.c
librc2_la_LDFLAGS =  $(module_ldflags)
