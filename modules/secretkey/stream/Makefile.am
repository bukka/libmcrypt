## Process this file with automake to produce Makefile.in
DEFS = @DEFS@ 

include ../common/Modules.inc

EXTRA_DIST = arcfour.h enigma.h panama.h wake.h

pkglib_LTLIBRARIES = @INSTALL_SECRETKEY_STREAM_MODULES@

EXTRA_LTLIBRARIES = arcfour.la enigma.la panama.la wake.la

noinst_LTLIBRARIES = @NOINSTALL_SECRETKEY_STREAM_MODULES@

arcfour_la_SOURCES = arcfour.c
arcfour_la_LDFLAGS = $(module_ldflags)
enigma_la_SOURCES = enigma.c
enigma_la_LDFLAGS = $(module_ldflags)
panama_la_SOURCES = panama.c
panama_la_LDFLAGS = $(module_ldflags)
wake_la_SOURCES = wake.c
wake_la_LDFLAGS = $(module_ldflags)
