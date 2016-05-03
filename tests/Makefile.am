## Process this file with automake to produce Makefile.in

check_PROGRAMS = signon-glib-testsuite
dist_check_SCRIPTS = signon-glib-test.sh

signon_glib_testsuite_SOURCES = check_signon.c
signon_glib_testsuite_CPPFLAGS = \
	-I$(top_srcdir) \
	$(DEPS_CFLAGS) \
	$(CHECK_FLAGS)
signon_glib_testsuite_LDADD = \
	$(top_builddir)/libsignon-glib/libsignon-glib.la \
	$(DEPS_LIBS) \
	$(CHECK_LIBS)

TESTS_ENVIRONMENT = \
	TESTDIR=$(top_srcdir)/tests/; export TESTDIR;

TESTS = signon-glib-test.sh
