## Process this file with automake to produce Makefile.in
DEFS = @DEFS@ 

include ../common/Modules.inc

EXTRA_DIST = serpent.h

pkglib_LTLIBRARIES = @INSTALL_SECRETKEY_BLOCK_MODULES@

EXTRA_LTLIBRARIES = serpent.la

noinst_LTLIBRARIES = @NOINSTALL_SECRETKEY_BLOCK_MODULES@

serpent_la_SOURCES = serpent.c
serpent_la_LDFLAGS = $(module_ldflags)
