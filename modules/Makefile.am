## Process this file with automake to produce Makefile.in

#SUBDIRS = publickey secretkey modes 
SUBDIRS = secretkey modes

noinst_LTLIBRARIES = libmcryptmod.la

libmcryptmod_la_SOURCES =
libmcryptmod_la_LIBADD = \
	secretkey/libmcryptsk.la \
	modes/libmcryptmodes.la
