## Process this file with automake to produce Makefile.in
DEFS = @DEFS@ 

include ${top_srcdir}/common/Modules.inc

EXTRA_DIST = wake.h

pkglib_LTLIBRARIES = @INSTALL_SECRETKEY_STREAM_MODULES@

EXTRA_LTLIBRARIES = libwake.la

noinst_LTLIBRARIES = @NOINSTALL_SECRETKEY_STREAM_MODULES@

libwake_la_SOURCES = wake.c
libwake_la_LDFLAGS = $(module_ldflags)
