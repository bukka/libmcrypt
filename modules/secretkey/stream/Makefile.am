## Process this file with automake to produce Makefile.in
DEFS = @DEFS@ 
INCLUDES = -I. -I../.. $(INCLTDL) -I../../lib

EXTRA_DIST = arcfour.h enigma.h panama.h wake.h

pkglib_LTLIBRARIES = @INSTALL_ALGORITHM_MODULES@

EXTRA_LTLIBRARIES = arcfour.la enigma.la panama.la wake.la

noinst_LTLIBRARIES = @NOINSTALL_ALGORITHM_MODULES@

arcfour_la_SOURCES = arcfour.c
arcfour_la_LDFLAGS =  -module -avoid-version -rpath $(pkglibdir)
enigma_la_SOURCES = enigma.c
enigma_la_LDFLAGS =  -module -avoid-version -rpath $(pkglibdir)
panama_la_SOURCES = panama.c
panama_la_LDFLAGS =  -module -avoid-version -rpath $(pkglibdir)
wake_la_SOURCES = wake.c
wake_la_LDFLAGS =  -module -avoid-version  -rpath $(pkglibdir)
