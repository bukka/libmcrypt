
## Process this file with automake to produce Makefile.in

AM_CPPFLAGS = $(INCLTDL)
EXTRA_DIST = KNOWN-BUGS THANKS NEWS libmcrypt.spec.in libmcrypt.spec COPYING.LIB

#DIST_SUBDIRS = libltdl modules lib src doc
#SUBDIRS = $(LIBLTDL_DIR) modules lib src doc

DIST_SUBDIRS = libltdl modules lib
SUBDIRS = $(LIBLTDL_DIR) modules lib

lib_LTLIBRARIES = libmcrypt.la

libmcrypt_la_SOURCES =
libmcrypt_la_LIBADD = \
	lib/libmcryptlib.la \
	modules/libmcryptmod.la
