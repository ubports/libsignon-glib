ACLOCAL_AMFLAGS = -I m4
DISTCHECK_CONFIGURE_FLAGS = \
	--enable-gtk-doc \
	--enable-introspection=yes
SUBDIRS = libsignon-glib docs tests

if ENABLE_PYTHON
SUBDIRS += pygobject
endif

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_in_files = libsignon-glib.pc.in
pkgconfig_DATA = $(pkgconfig_in_files:.pc.in=.pc)

dist_noinst_DATA = \
	$(libsignondoc_DATA) \
	m4/introspection.m4

DISTCLEANFILES = \
	$(pkgconfig_DATA)
