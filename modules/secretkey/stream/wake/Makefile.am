## Process this file with automake to produce Makefile.in
DEFS = @DEFS@ 

include ${top_srcdir}/common/Modules.inc

EXTRA_DIST = wake.h

pkglib_LTLIBRARIES = @INSTALL_SECRETKEY_STREAM_MODULES@

lib_LTLIBRARIES = wake.la

noinst_LTLIBRARIES = @NOINSTALL_SECRETKEY_STREAM_MODULES@

wake_la_SOURCES = wake.c
wake_la_LDFLAGS = $(module_ldflags)
