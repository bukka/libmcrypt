module_ldflags = -module -avoid-version -rpath $(pkglibdir)

INCLUDES = -I. -I../common -I../../common $(INCLTDL) -I$(top_srcdir)/lib

