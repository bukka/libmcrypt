## Process this file with automake to produce Makefile.in
DEFS = @DEFS@ 

include ../common/Modules.inc

EXTRA_DIST = arcfour.h

pkglib_LTLIBRARIES = @INSTALL_SECRETKEY_STREAM_MODULES@

EXTRA_LTLIBRARIES = arcfour.la

noinst_LTLIBRARIES = @NOINSTALL_SECRETKEY_STREAM_MODULES@

arcfour_la_SOURCES = arcfour.c
arcfour_la_LDFLAGS = $(module_ldflags)
