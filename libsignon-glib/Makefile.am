lib_LTLIBRARIES = \
	libsignon-glib.la

libsignon_glib_la_CPPFLAGS = \
	-I$(top_srcdir) \
	-I$(srcdir) \
	-I$(top_builddir) \
	-I$(builddir)
libsignon_glib_la_CFLAGS = \
	$(DEPS_CFLAGS) \
	$(COVERAGE_CFLAGS) \
	-Wall -Werror -Wno-error=deprecated-declarations
libsignon_glib_la_LIBADD = $(DEPS_LIBS)
libsignon_glib_la_LDFLAGS = \
	$(COVERAGE_LDFLAGS) \
	-version-info 1:0:0 \
	-export-symbols-regex '^signon_'

nodist_libsignon_glib_la_SOURCES = \
	signon-marshal.c \
	signon-marshal.h \
	signon-enum-types.h \
	signon-enum-types.c \
	signon-errors-enum.c \
	sso-auth-service-gen.c \
	sso-auth-service-gen.h \
	sso-auth-session-gen.c \
	sso-auth-session-gen.h \
	sso-identity-gen.c \
	sso-identity-gen.h \
	stamp-signon-enum-types.h

BUILT_SOURCES = \
	$(nodist_libsignon_glib_la_SOURCES) \
	signon-errors-map.c

CLEANFILES = \
	$(BUILT_SOURCES) \
	sso-auth-service-gen-doc-com.google.code.AccountsSSO.SingleSignOn.AuthService.xml \
	sso-auth-session-gen-doc-com.google.code.AccountsSSO.SingleSignOn.AuthSession.xml \
	sso-identity-gen-doc-com.google.code.AccountsSSO.SingleSignOn.Identity.xml

libsignon_glib_la_SOURCES = \
	signon-auth-service.h \
	signon-identity-info.h \
	signon-identity.h \
	signon-auth-session.h \
	signon-internals.h \
	signon-auth-service.c \
	signon-identity-info.c \
	signon-identity.c \
	signon-auth-session.c \
	signon-errors.h \
	signon-errors.c \
	signon-proxy.c \
	signon-proxy.h \
	signon-utils.h \
	signon-utils.c \
	signon-types.h \
	sso-auth-service.c \
	sso-auth-service.h

libsignon_glib_includedir = $(includedir)/libsignon-glib
libsignon_glib_include_HEADERS = \
	signon-auth-service.h \
	signon-auth-session.h \
	signon-identity-info.h \
	signon-identity.h \
	signon-errors.h \
	signon-enum-types.h \
	signon-glib.h \
	signon-types.h \
	$(signon_headers)

# Headers with enums to be parsed with glib-mkenums;
# signon-errors.h is handled separately
libsignon_glib_headers_with_enums = \
	signon-auth-session.h \
	signon-identity-info.h

DBUS_INTERFACES_DIR = $(datadir)/dbus-1/interfaces

sso-auth-service-gen.h sso-auth-service-gen.c: $(DBUS_INTERFACES_DIR)/com.google.code.AccountsSSO.SingleSignOn.AuthService.xml
	$(AM_V_GEN)gdbus-codegen \
		--generate-c-code sso-auth-service-gen \
		--generate-docbook sso-auth-service-gen-doc \
		--annotate "com.google.code.AccountsSSO.SingleSignOn.AuthService" org.gtk.GDBus.C.Name SsoAuthService \
		$<

sso-auth-session-gen.h sso-auth-session-gen.c: $(DBUS_INTERFACES_DIR)/com.google.code.AccountsSSO.SingleSignOn.AuthSession.xml
	$(AM_V_GEN)gdbus-codegen \
		--generate-c-code sso-auth-session-gen \
		--generate-docbook sso-auth-session-gen-doc \
		--annotate "com.google.code.AccountsSSO.SingleSignOn.AuthSession" org.gtk.GDBus.C.Name SsoAuthSession \
		$<

sso-identity-gen.h sso-identity-gen.c: $(DBUS_INTERFACES_DIR)/com.google.code.AccountsSSO.SingleSignOn.Identity.xml
	$(AM_V_GEN)gdbus-codegen \
		--generate-c-code sso-identity-gen \
		--generate-docbook sso-identity-gen-doc \
		--annotate "com.google.code.AccountsSSO.SingleSignOn.Identity" org.gtk.GDBus.C.Name SsoIdentity \
		$<

signon-marshal.h: signon-marshal.list Makefile
	$(AM_V_GEN)glib-genmarshal --header --prefix=_signon_marshal $< > $@

signon-marshal.c: signon-marshal.list Makefile
	$(AM_V_GEN)glib-genmarshal --body --prefix=_signon_marshal $< > $@

signon-enum-types.h: stamp-signon-enum-types.h
	$(AM_V_at)true

stamp-signon-enum-types.h: Makefile \
	$(libsignon_glib_headers_with_enums) signon-errors.h
	$(AM_V_GEN)( cd $(srcdir) &&  glib-mkenums \
	    --fhead "#ifndef __SIGNON_ENUM_TYPES_H__\n#define __SIGNON_ENUM_TYPES_H__\n#include <glib-object.h>\n\nG_BEGIN_DECLS\n" \
	    --fprod "/* enumerations from \"@filename@\" */\n" \
	    --vhead "GType @enum_name@_get_type (void) G_GNUC_CONST;\n#define SIGNON_TYPE_@ENUMSHORT@ (@enum_name@_get_type())\n" \
	    --ftail "G_END_DECLS\n\n#endif /* __SIGNON_ENUM_TYPES_H__ */" \
	    $(libsignon_glib_headers_with_enums) signon-errors.h ) >> xgen-geth \
	    && (cmp -s xgen-geth signon-enum-types.h || cp xgen-geth signon-enum-types.h ) \
	    && rm -f xgen-geth \
	    && echo timestamp > $(@F)

signon-enum-types.c: Makefile $(libsignon_glib_headers_with_enums)
	$(AM_V_GEN)( cd $(srcdir) && glib-mkenums \
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
	$(AM_V_GEN)( cd $(srcdir) && glib-mkenums \
	    --fhead "#include \"signon-enum-types.h\"\n#include \"signon-errors.h\"\n#include \"signoncommon.h\"\n#define g_intern_static_string(s) (s)\n" \
	    --fprod "\n/* enumerations from \"@filename@\" */" \
	    --ftail "\n#define __SIGNON_ENUM_TYPES_C__\n" \
	    --vhead "GType\n@enum_name@_get_type (void)\n{\n  static GType etype = 0;\n  if (etype == 0) {\n    static const G@Type@Value values[] = {" \
	    --vprod "      { @VALUENAME@, SED@VALUENAME@, \"@valuenick@\" }," \
	    --vtail "      { 0, NULL, NULL }\n    };\n    etype = g_@type@_register_static (g_intern_static_string (\"@EnumName@\"), values);\n  }\n  return etype;\n}\n" \
	    signon-errors.h ) | \
	    $(SED) -e 's/SEDSIGNON_ERROR_\([^,]*\)/SIGNOND_\1_ERR_NAME/' \
	    > xgen-getc-enum \
	    && cp xgen-getc-enum signon-errors-enum.c  \
	    && rm -f xgen-getc-enum

signon-errors-map.c: Makefile signon-errors.h
	$(AM_V_GEN)( cd $(srcdir) && \
	  echo "static const GDBusErrorEntry signon_error_entries[] = {" && \
	  grep "^ *SIGNON_ERROR_" signon-errors.h | \
	    $(SED) -e 's/SIGNON_ERROR_\([A-Z_0-9]*\).*/{ SIGNON_ERROR_\1, SIGNOND_\1_ERR_NAME },/' && \
	  echo -e "};\n" ) > signon-errors-map.c

dist_noinst_DATA = \
	signon-marshal.list \
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
Signon_1_0_gir_INCLUDES = GObject-2.0 Gio-2.0
Signon_1_0_gir_SCANNERFLAGS = \
	--identifier-prefix=Signon \
	--symbol-prefix=signon \
	--c-include="libsignon-glib/signon-glib.h" \
	--warn-all
Signon_1_0_gir_CFLAGS = \
	-I$(top_srcdir) \
	-I$(top_builddir) \
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

# Vala bindings
vapidir = $(datadir)/vala/vapi
dist_vapi_DATA = \
	signon.vapi
