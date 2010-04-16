INCLUDES = $(DBUS_CFLAGS) -I$(top_srcdir) \
	   -DLIBDIR="@libdir@" -DLIBVERSION="0"
lib_LTLIBRARIES = \
	libsignon-glib.la

libsignon_glib_la_CFLAGS = $(DEPS_CFLAGS) -Wall -Werror
libsignon_glib_la_LIBADD = $(DEPS_LIBS)
libsignon_glib_la_LDFLAGS = -version-info 0:1:0

BUILT_SOURCES = \
	signon-marshal.c \
	signon-marshal.h \
	signon-client-glib-gen.h \
	signon-identity-glib-gen.h \
	signon-auth-session-client-glib-gen.h \
	signon-enum-types.h \
	signon-enum-types.c \
	stamp-signon-enum-types.h

CLEANFILES = $(BUILT_SOURCES)

libsignon_glib_la_SOURCES = \
	signon-auth-service.h \
	signon-identity.h \
	signon-dbus-queue.h \
	signon-auth-session.h \
	signon-internals.h \
	signon-auth-service.c \
	signon-identity.c \
	signon-dbus-queue.c \
	signon-auth-session.c \
	signon-errors.h \
	signon-errors.c \
	signon-proxy.h \
	signon-proxy.c \
	signon-utils.h \
	signon-utils.c \
	$(BUILT_SOURCES)

libsignon_glib_includedir = $(includedir)/libsignon-glib
libsignon_glib_include_HEADERS = \
	signon-auth-service.h \
	signon-auth-session.h \
	signon-identity.h \
	signon-errors.h \
	$(signon_headers)

signon-client-glib-gen.h: signondaemon.xml
	dbus-binding-tool --prefix=signon-client-glib --mode=glib-client $< > $@

signon-auth-session-client-glib-gen.h: signonauthsession.xml
	dbus-binding-tool --prefix=signon-auth-session-client-glib --mode=glib-client $< > $@

signon-identity-glib-gen.h: signonidentity.xml
	dbus-binding-tool --prefix=signon-identity-glib --mode=glib-client $< > $@

%-marshal.h: %-marshal.list Makefile
	glib-genmarshal --header --prefix=$(subst -,_,$*)_marshal $< > $*-marshal.h

%-marshal.c: %-marshal.list Makefile
	glib-genmarshal --body --prefix=$(subst -,_,$*)_marshal $< > $*-marshal.c

signon-enum-types.h: stamp-signon-enum-types.h
	@true

stamp-signon-enum-types.h: Makefile signon-errors.h
	( cd $(srcdir) &&  glib-mkenums \
	    --fhead "#ifndef __SIGNON_ENUM_TYPES_H__\n#define __SIGNON_ENUM_TYPES_H__\n#include <glib-object.h>\n\nG_BEGIN_DECLS\n" \
	    --fprod "/* enumerations from \"@filename@\" */\n" \
	    --vhead "GType @enum_name@_get_type (void) G_GNUC_CONST;\n#define SIGNON_TYPE_@ENUMSHORT@ (@enum_name@_get_type())\n" \
	    --ftail "G_END_DECLS\n\n#endif /* __SIGNON_ENUM_TYPES_H__ */" \
	    signon-errors.h ) >> xgen-geth \
	    && (cmp -s xgen-geth signon-enum-types.h || cp xgen-geth signon-enum-types.h ) \
	    && rm -f xgen-geth \
	    && echo timestamp > $(@F)

signon-enum-types.c: Makefile signon-errors.h
	( cd $(srcdir) && glib-mkenums \
	    --fhead "#include \"signon-enum-types.h\"\n#include \"signon-errors.h\"\n#define g_intern_static_string(s) (s)\n" \
	    --fprod "\n/* enumerations from \"@filename@\" */" \
	    --ftail "\n#define __SIGNON_ENUM_TYPES_C__\n" \
	    --vhead "GType\n@enum_name@_get_type (void)\n{\n  static GType etype = 0;\n  if (etype == 0) {\n    static const G@Type@Value values[] = {" \
	    --vprod "      { @VALUENAME@, \"@VALUENAME@\", \"@valuenick@\" }," \
	    --vtail "      { 0, NULL, NULL }\n    };\n    etype = g_@type@_register_static (g_intern_static_string (\"@EnumName@\"), values);\n  }\n  return etype;\n}\n" \
	    signon-errors.h ) > xgen-getc \
	    && cp xgen-getc signon-enum-types.c  \
	    && rm -f xgen-getc

EXTRA_DIST = signon-marshal.list \
	     stamp-signon-enum-types.h
