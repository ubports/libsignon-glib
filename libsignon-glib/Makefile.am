INCLUDES = $(DBUS_CFLAGS) -I$(top_srcdir) \
	   -DLIBDIR="@libdir@" -DLIBVERSION="0"
lib_LTLIBRARIES = \
	libsignon-glib.la

libsignon_glib_la_CFLAGS = \
	-I$(top_srcdir) \
	$(DEPS_CFLAGS) \
	-Wall -Werror

if ENABLE_PYTHON
libsignon_glib_la_CFLAGS += -DENABLE_PYGOBJECT_HACK
endif

libsignon_glib_la_LIBADD = $(DEPS_LIBS)
libsignon_glib_la_LDFLAGS = \
	-version-info 1:0:0 \
	-export-symbols-regex '^signon_'

BUILT_SOURCES = \
	signon-marshal.c \
	signon-marshal.h \
	signon-client-glib-gen.h \
	signon-identity-glib-gen.h \
	signon-auth-session-client-glib-gen.h \
	signon-enum-types.h \
	signon-enum-types.c \
	signon-errors-enum.c \
	stamp-signon-enum-types.h

CLEANFILES = $(BUILT_SOURCES)

libsignon_glib_la_SOURCES = \
	signon-auth-service.h \
	signon-identity-info.h \
	signon-identity.h \
	signon-dbus-queue.h \
	signon-auth-session.h \
	signon-internals.h \
	signon-auth-service.c \
	signon-identity-info.c \
	signon-identity.c \
	signon-dbus-queue.c \
	signon-auth-session.c \
	signon-errors.h \
	signon-errors.c \
	signon-proxy.h \
	signon-proxy.c \
	signon-utils.h \
	signon-utils.c

nodist_libsignon_glib_la_SOURCES = \
	$(BUILT_SOURCES)

libsignon_glib_includedir = $(includedir)/libsignon-glib
libsignon_glib_include_HEADERS = \
	signon-auth-service.h \
	signon-auth-session.h \
	signon-identity-info.h \
	signon-identity.h \
	signon-errors.h \
	signon-enum-types.h \
	signon-glib.h \
	$(signon_headers)

# Headers with enums to be parsed with glib-mkenums;
# signon-errors.h is handled separately
libsignon_glib_headers_with_enums = \
	signon-auth-session.h \
	signon-identity-info.h

DBUS_INTERFACES_DIR = /usr/share/dbus-1/interfaces

signon-client-glib-gen.h: $(DBUS_INTERFACES_DIR)/com.nokia.SingleSignOn.AuthService.xml
	dbus-binding-tool --prefix=signon-client-glib --mode=glib-client $< \
	| sed s/com_nokia_SingleSignOn/SSO/g > $@

signon-auth-session-client-glib-gen.h: $(DBUS_INTERFACES_DIR)/com.nokia.SingleSignOn.AuthSession.xml
	dbus-binding-tool --prefix=signon-auth-session-client-glib --mode=glib-client $< \
	| sed s/com_nokia_SingleSignOn/SSO/g > $@

signon-identity-glib-gen.h: $(DBUS_INTERFACES_DIR)/com.nokia.SingleSignOn.Identity.xml
	dbus-binding-tool --prefix=signon-identity-glib --mode=glib-client $< \
	| sed s/com_nokia_SingleSignOn/SSO/g > $@

%-marshal.h: %-marshal.list Makefile
	glib-genmarshal --header --prefix=_$(subst -,_,$*)_marshal $< > $*-marshal.h

%-marshal.c: %-marshal.list Makefile
	glib-genmarshal --body --prefix=_$(subst -,_,$*)_marshal $< > $*-marshal.c

signon-enum-types.h: stamp-signon-enum-types.h
	@true

stamp-signon-enum-types.h: Makefile \
	$(libsignon_glib_headers_with_enums) signon-errors.h
	( cd $(srcdir) &&  glib-mkenums \
	    --fhead "#ifndef __SIGNON_ENUM_TYPES_H__\n#define __SIGNON_ENUM_TYPES_H__\n#include <glib-object.h>\n\nG_BEGIN_DECLS\n" \
	    --fprod "/* enumerations from \"@filename@\" */\n" \
	    --vhead "GType @enum_name@_get_type (void) G_GNUC_CONST;\n#define SIGNON_TYPE_@ENUMSHORT@ (@enum_name@_get_type())\n" \
	    --ftail "G_END_DECLS\n\n#endif /* __SIGNON_ENUM_TYPES_H__ */" \
	    $(libsignon_glib_headers_with_enums) signon-errors.h ) >> xgen-geth \
	    && (cmp -s xgen-geth signon-enum-types.h || cp xgen-geth signon-enum-types.h ) \
	    && rm -f xgen-geth \
	    && echo timestamp > $(@F)

signon-enum-types.c: Makefile $(libsignon_glib_headers_with_enums)
	( cd $(srcdir) && glib-mkenums \
	    --fhead "#include \"signon-enum-types.h\"\n" \
	    --fhead "#include \"signon-identity-info.h\"\n" \
			--fhead "#include \"signon-auth-session.h\"\n" \
			--fhead "#define g_intern_static_string(s) (s)\n" \
	    --fprod "\n/* enumerations from \"@filename@\" */" \
	    --ftail "\n#define __SIGNON_ENUM_TYPES_C__\n" \
	    --vhead "GType\n@enum_name@_get_type (void)\n{\n  static GType etype = 0;\n  if (etype == 0) {\n    static const G@Type@Value values[] = {" \
	    --vprod "      { @VALUENAME@, \"@VALUENAME@\", \"@valuenick@\" }," \
	    --vtail "      { 0, NULL, NULL }\n    };\n    etype = g_@type@_register_static (g_intern_static_string (\"@EnumName@\"), values);\n  }\n  return etype;\n}\n" \
	    $(libsignon_glib_headers_with_enums) ) > xgen-getc \
	    && cp xgen-getc signon-enum-types.c  \
	    && rm -f xgen-getc

signon-errors-enum.c: Makefile signon-errors.h
	( cd $(srcdir) && glib-mkenums \
	    --fhead "#include \"signon-enum-types.h\"\n#include \"signon-errors.h\"\n#include \"signoncommon.h\"\n#define g_intern_static_string(s) (s)\n" \
	    --fprod "\n/* enumerations from \"@filename@\" */" \
	    --ftail "\n#define __SIGNON_ENUM_TYPES_C__\n" \
	    --vhead "GType\n@enum_name@_get_type (void)\n{\n  static GType etype = 0;\n  if (etype == 0) {\n    static const G@Type@Value values[] = {" \
	    --vprod "      { @VALUENAME@, SED@VALUENAME@, \"@valuenick@\" }," \
	    --vtail "      { 0, NULL, NULL }\n    };\n    etype = g_@type@_register_static (g_intern_static_string (\"@EnumName@\"), values);\n  }\n  return etype;\n}\n" \
	    signon-errors.h ) | \
	    sed -e 's/SEDSIGNON_ERROR_\([^,]*\)/SIGNOND_\1_ERR_NAME/' \
	    > xgen-getc \
	    && cp xgen-getc signon-errors-enum.c  \
	    && rm -f xgen-getc

EXTRA_DIST = signon-marshal.list \
	     stamp-signon-enum-types.h

-include $(INTROSPECTION_MAKEFILE)
INTROSPECTION_GIRS =
INTROSPECTION_SCANNER_ARGS = --add-include-path=$(srcdir)
INTROSPECTION_COMPILER_ARGS = --includedir=$(srcdir)

if HAVE_INTROSPECTION
introspection_sources = \
	signon-auth-service.c \
	signon-auth-service.h \
	signon-auth-session.c \
	signon-auth-session.h \
	signon-enum-types.h \
	signon-enum-types.c \
	signon-errors.c \
	signon-errors.h \
	signon-identity-info.c \
	signon-identity-info.h \
	signon-identity.c \
	signon-identity.h

Signon-1.0.gir: libsignon-glib.la
Signon_1_0_gir_INCLUDES = GObject-2.0
Signon_1_0_gir_SCANNERFLAGS = \
	--identifier-prefix=Signon \
	--symbol-prefix=signon \
	--c-include="libsignon-glib/signon-glib.h" \
	--warn-all
Signon_1_0_gir_CFLAGS = \
	-I$(top_srcdir) \
	$(DEPS_CFLAGS)
Signon_1_0_gir_LIBS = libsignon-glib.la
Signon_1_0_gir_FILES = $(introspection_sources)
INTROSPECTION_GIRS += Signon-1.0.gir

girdir = $(datadir)/gir-1.0
gir_DATA = $(INTROSPECTION_GIRS)

typelibdir = $(libdir)/girepository-1.0
typelib_DATA = $(INTROSPECTION_GIRS:.gir=.typelib)

CLEANFILES += $(gir_DATA) $(typelib_DATA)
endif
