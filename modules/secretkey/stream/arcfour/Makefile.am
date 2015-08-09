## Process this file with automake to produce Makefile.in
DEFS = @DEFS@ 

include ${top_srcdir}/common/Modules.inc

EXTRA_DIST = arcfour.h

pkglib_LTLIBRARIES = @INSTALL_SECRETKEY_STREAM_MODULES@

EXTRA_LTLIBRARIES = libarcfour.la

noinst_LTLIBRARIES = @NOINSTALL_SECRETKEY_STREAM_MODULES@

libarcfour_la_SOURCES = arcfour.c
libarcfour_la_LDFLAGS = $(module_ldflags)
