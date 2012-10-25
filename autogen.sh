#!/bin/sh -e

srcdir=`dirname $0`
test -z "$srcdir" && srcdir=.

(test -f $srcdir/libsignon-glib.pc.in ) || {
	echo -n "Error: Directory "\`$srcdir\`" does not look like the "
        echo "top-level libsignon-glib directory."
	exit 1
}

gtkdocize --copy --flavour no-tmpl
autoreconf --install --force
. $srcdir/configure "$@"
