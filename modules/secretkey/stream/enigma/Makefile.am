## Process this file with automake to produce Makefile.in
DEFS = @DEFS@ 

include ${top_srcdir}/common/Modules.inc

EXTRA_DIST = enigma.h

pkglib_LTLIBRARIES = @INSTALL_SECRETKEY_STREAM_MODULES@

EXTRA_LTLIBRARIES = libenigma.la

noinst_LTLIBRARIES = @NOINSTALL_SECRETKEY_STREAM_MODULES@

libenigma_la_SOURCES = enigma.c
libenigma_la_LDFLAGS = $(module_ldflags)
