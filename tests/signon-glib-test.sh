#!/bin/sh

# Environment variables for the signon daemon
export SSO_LOGGING_LEVEL=2
export SSO_STORAGE_PATH="/tmp"
export SSO_DAEMON_TIMEOUT=1
export SSO_IDENTITY_TIMEOUT=3
export SSO_AUTHSESSION_TIMEOUT=3
export SSO_EXTENSIONS_DIR="/tmp" # this disables all extensions

#Environment variables for the test application
export G_MESSAGES_DEBUG=all
# If running the test executable under a wrapper, setup the tests so that the
# wrapper can debug them more easily.
if [ -n "$WRAPPER" ]; then
    export G_SLICE=always-malloc
    export CK_FORK="no"
else
    export G_SLICE=debug-blocks
fi

TEST_APP="$TESTDIR/signon-glib-test-wrapper.sh"

# If dbus-test-runner exists, use it to run the tests in a separate D-Bus
# session
if command -v dbus-test-runner > /dev/null ; then
    echo "Using dbus-test-runner"
    dbus-test-runner -m 180 --keep-env \
        -t signond -r \
        -t "$TEST_APP" -f com.google.code.AccountsSSO.SingleSignOn
else
    echo "Using existing D-Bus session"
    pkill signond || true
    trap "pkill -9 signond" EXIT
    signond &
    sleep 2

    $TEST_APP
fi
