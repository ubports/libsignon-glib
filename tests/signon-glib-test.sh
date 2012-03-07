#!/bin/sh

if test -z "$DBUS_SESSION_BUS_ADDRESS" ; then
    echo "No D-Bus session active; skipping tests."
    exit 0
fi

export G_MESSAGES_DEBUG=all

signon-glib-testsuite
