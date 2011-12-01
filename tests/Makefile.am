## Process this file with automake to produce Makefile.in

INCLUDES=-I$(top_srcdir) $(DEPS_CFLAGS)

bin_PROGRAMS = signon-glib-testsuite
bin_SCRIPTS = signon-glib-test.sh
CLEANFILES = $(bin_SCRIPTS)

signon_glib_testsuite_SOURCES = check_signon.c
signon_glib_testsuite_CFLAGS = $(CHECK_FLAGS) -I$(top_srcdir)
signon_glib_testsuite_LDADD = \
	$(CHECK_LIBS) \
	$(DEPS_LIBS) \
	$(top_builddir)/libsignon-glib/libsignon-glib.la

TESTS = signon-glib-testsuite

testdata_DATA = tests.xml

EXTRA_DIST = \
	$(testdata_DATA)
