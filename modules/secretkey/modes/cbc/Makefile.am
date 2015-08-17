## Process this file with automake to produce Makefile.in
DEFS = @DEFS@ 
AM_CPPFLAGS = -I. -I../../../.. $(INCLTDL) -I../../../../lib

EXTRA_DIST = cbc.h

noinst_LTLIBRARIES = libmcryptskmcbc.la

libmcryptskmcbc_la_SOURCES = cbc.c
libmcryptskmcbc_la_LDFLAGS = -module -avoid-version
