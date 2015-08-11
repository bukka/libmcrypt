## Process this file with automake to produce Makefile.in
DEFS = @DEFS@ 
AM_CPPFLAGS = -I. -I../.. $(INCLTDL) -I../../lib

EXTRA_DIST = ofb.h cfb.h nofb.h cbc.h ecb.h stream.h # ncfb.h ctr.h

noinst_LTLIBRARIES = \
	libmcryptmodes.la \
	libofb.la \
	libcfb.la \
	libnofb.la \
	libcbc.la \
	libecb.la \
	libstream.la #ncfb.la ctr.la

libmcryptmodes_la_SOURCES =
libmcryptmodes_la_LIBADD = \
	libofb.la \
	libcfb.la \
	libnofb.la \
	libcbc.la \
	libecb.la \
	libstream.la # libncfb.la libctrl.lo

libofb_la_SOURCES = ofb.c
libofb_la_LDFLAGS =  -module -avoid-version  -rpath $(pkglibdir)
#libctr_la_SOURCES = ctr.c
#libctr_la_LDFLAGS =  -module -avoid-version -rpath $(pkglibdir)
libcfb_la_SOURCES = cfb.c
libcfb_la_LDFLAGS =  -module -avoid-version -rpath $(pkglibdir)
#libncfb_la_SOURCES = ncfb.c
#libncfb_la_LDFLAGS =  -module -avoid-version -rpath $(pkglibdir)
libnofb_la_SOURCES = nofb.c
libnofb_la_LDFLAGS =  -module -avoid-version -rpath $(pkglibdir)
libecb_la_SOURCES = ecb.c
libecb_la_LDFLAGS =  -module -avoid-version -rpath $(pkglibdir)
libcbc_la_SOURCES = cbc.c
libcbc_la_LDFLAGS =  -module -avoid-version -rpath $(pkglibdir)
libstream_la_SOURCES = stream.c
libstream_la_LDFLAGS =  -module -avoid-version -rpath $(pkglibdir)
