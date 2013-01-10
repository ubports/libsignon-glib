dnl Process this file with autoconf to produce a configure script.
AC_PREREQ([2.64])
AC_INIT([libsignon-glib],
        [1.8],
        [http://code.google.com/p/accounts-sso/issues/entry],
        [libsignon-glib],
        [http://code.google.com/p/accounts-sso/])

AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_SRCDIR([libsignon-glib.pc.in])
AC_CONFIG_MACRO_DIR([m4])

AM_INIT_AUTOMAKE([1.11 -Wall nostdinc silent-rules subdir-objects])

AC_PROG_CC
AC_PROG_CC_STDC
AM_PROG_CC_C_O

LT_PREREQ([2.2])
LT_INIT([disable-static])

# Gobject Introspection
GOBJECT_INTROSPECTION_CHECK([1.30.0])

PKG_CHECK_MODULES(
    [DEPS],
    [gio-2.0 >= 2.30
     gio-unix-2.0
     glib-2.0 >= 2.32
     gobject-2.0
     signond >= 8.40])
AC_SUBST(DEPS_CFLAGS)
AC_SUBST(DEPS_LIBS)

# Build tests.

CHECK_REQUIRED="check >= 0.9.4"

AC_ARG_ENABLE([tests],
  [AS_HELP_STRING([--disable-tests], [build with testing support disabled])])

AS_IF([test "x$enable_tests" != "xno"],
  [PKG_CHECK_EXISTS([$CHECK_REQUIRED], [have_check=yes], [have_check=no])],
  [have_check=no])

AS_IF([test "x$have_check" = "xyes"],
  [PKG_CHECK_MODULES([CHECK], [$CHECK_REQUIRED])
   AC_SUBST([CHECK_CFLAGS])
   AC_SUBST([CHECK_LIBS])],
  [AS_IF([test "x$enable_tests" = "xyes"],
    [AC_MSG_ERROR([tests enabled but required dependencies were not found])])])

AM_CONDITIONAL([ENABLE_TESTS], [test "x$have_check" = "xyes"])

GTK_DOC_CHECK([1.14], [--flavour no-tmpl])

AC_ARG_ENABLE([cast-checks],
    [AS_HELP_STRING([--disable-cast-checks], [compile with GLib cast checks disabled])])
AS_IF([test "x$enable_cast_checks" = "xno"],
    [CFLAGS="$CFLAGS -DG_DISABLE_CAST_CHECKS"])

AC_ARG_ENABLE([asserts],
    [AS_HELP_STRING([--disable-asserts], [compile with GLib assertions disabled])])
AS_IF([test "x$enable_asserts" = "xno"],
    [CFLAGS="$CFLAGS -DG_DISABLE_ASSERTS"])

AC_ARG_ENABLE([checks],
    [AS_HELP_STRING([--disable-checks], [compile with GLib checks disabled])])
AS_IF([test "x$checks" = "xno"],
    [CFLAGS="$CFLAGS -DG_DISABLE_CHECKS"])

AC_ARG_ENABLE([debug],
    [AS_HELP_STRING([--enable-debug], [enable printing of debug messages])])
AS_IF([test "x$enable_debug" = "xyes"],
    [CFLAGS="$CFLAGS -DENABLE_DEBUG"])

AC_ARG_ENABLE([coverage],
    [AS_HELP_STRING([--enable-coverage], [compile with coverage info])])
AS_IF([test "x$enable_coverage" = "xyes"],
    [CFLAGS="$CFLAGS -g -fprofile-arcs -ftest-coverage"])

# Python support.
PYGOBJECT_REQUIRED=2.90

AC_ARG_ENABLE([python],
              [AS_HELP_STRING([--enable-python], [Build with python support])])

AS_IF([test "x$enable_python" != "xno"],
    [PKG_CHECK_EXISTS([pygobject-3.0 >= $PYGOBJECT_REQUIRED],
                      [have_python=yes], [have_python=no])])

AS_IF([test "x$have_python" = "xyes"],
    [AM_PATH_PYTHON
     AC_SUBST([pyoverridesdir], [`$PYTHON -c "import gi;print gi._overridesdir"`])])

AM_CONDITIONAL([ENABLE_PYTHON], [test "x$have_python" = "xyes"])

AC_CONFIG_FILES([
	Makefile
	libsignon-glib/Makefile
	libsignon-glib.pc
	docs/Makefile
	docs/reference/Makefile
	docs/reference/version.xml
	tests/Makefile
	pygobject/Makefile
])
AC_OUTPUT
