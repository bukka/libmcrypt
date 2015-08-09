## Process this file with automake to produce Makefile.in
DEFS = @DEFS@ 

include ${top_srcdir}/common/Modules.inc

EXTRA_DIST = panama.h

pkglib_LTLIBRARIES = @INSTALL_SECRETKEY_STREAM_MODULES@

EXTRA_LTLIBRARIES = libpanama.la

noinst_LTLIBRARIES = @NOINSTALL_SECRETKEY_STREAM_MODULES@

libpanama_la_SOURCES = panama.c
libpanama_la_LDFLAGS = $(module_ldflags)
