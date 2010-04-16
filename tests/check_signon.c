/**
 * Copyright (C) 2009 Nokia Corporation.
 * Contact: Alberto Mardegan <alberto.mardegan@nokia.com>
 * Licensed under the terms of Nokia EUSA (see the LICENSE file)
 */

/**
 * @example check_signon.c
 * Shows how to initialize the framework.
 */
#include "libsignon-glib/signon-internals.h"
#include "libsignon-glib/signon-auth-service.h"
#include "libsignon-glib/signon-auth-session.h"
#include "libsignon-glib/signon-identity.h"
#include "libsignon-glib/signon-client-glib-gen.h"
#include "libsignon-glib/signon-identity-glib-gen.h"
#include "libsignon-glib/signon-errors.h"

#include <glib.h>
#include <check.h>
#include <stdlib.h>
#include <string.h>
#include <dbus/dbus-glib.h>

static GMainLoop *main_loop = NULL;
static SignonIdentity *identity = NULL;
static SignonAuthService *auth_service = NULL;

static void
end_test ()
{
    if (auth_service)
    {
        g_object_unref (auth_service);
        auth_service = NULL;
    }

    if (identity)
    {
        g_object_unref (identity);
        identity = NULL;
    }

    if (main_loop)
    {
        g_main_loop_quit (main_loop);
        g_main_loop_unref (main_loop);
        main_loop = NULL;
    }
}

START_TEST(test_init)
{
    g_type_init ();

    auth_service = signon_auth_service_new ();
    main_loop = g_main_loop_new (NULL, FALSE);

    fail_unless (SIGNON_IS_AUTH_SERVICE (auth_service),
                 "Failed to initialize the AuthService.");
    end_test ();
}
END_TEST

static void
signon_query_methods_cb (SignonAuthService *auth_service, gchar **methods,
                         GError *error, gpointer user_data)
{
    if (error)
    {
        g_warning ("%s: %s", G_STRFUNC, error->message);
        g_main_loop_quit (main_loop);
        fail();
    }

    gboolean has_sasl = FALSE;

    fail_unless (g_strcmp0 (user_data, "Hello") == 0, "Got wrong string");
    fail_unless (methods != NULL, "The methods does not exist");

    while (*methods)
    {
        if (g_strcmp0 (*methods, "sasl") == 0)
        {
            has_sasl = TRUE;
            break;
        }
        methods++;
    }
    fail_unless (has_sasl, "sasl method does not exist");

    g_main_loop_quit (main_loop);
}

START_TEST(test_query_methods)
{
    g_type_init ();

    if(!main_loop)
        main_loop = g_main_loop_new (NULL, FALSE);

    auth_service = signon_auth_service_new ();

    fail_unless (SIGNON_IS_AUTH_SERVICE (auth_service),
                 "Failed to initialize the AuthService.");

    signon_auth_service_query_methods (auth_service, (SignonQueryMethodsCb)signon_query_methods_cb, "Hello");
    g_main_loop_run (main_loop);
    end_test ();
}
END_TEST

static void
signon_query_mechanisms_cb (SignonAuthService *auth_service, gchar *method,
        gchar **mechanisms, GError *error, gpointer user_data)
{
    if (error)
    {
        g_warning ("%s: %s", G_STRFUNC, error->message);
        g_main_loop_quit (main_loop);
        fail();
    }

    gboolean has_plain = FALSE;
    gboolean has_digest = FALSE;

    fail_unless (strcmp (user_data, "Hello") == 0, "Got wrong string");
    fail_unless (mechanisms != NULL, "The mechanisms does not exist");

    while (*mechanisms)
    {
        if (g_strcmp0 (*mechanisms, "PLAIN") == 0)
            has_plain = TRUE;

        if (g_strcmp0 (*mechanisms, "DIGEST-MD5") == 0)
            has_digest = TRUE;

        mechanisms++;
    }


    fail_unless (has_plain, "PLAIN mechanism does not exist");
    fail_unless (has_digest, "DIGEST-MD5 mechanism does not exist");

    g_main_loop_quit (main_loop);
}

START_TEST(test_query_mechanisms)
{
    g_type_init ();

    auth_service = signon_auth_service_new ();

    fail_unless (SIGNON_IS_AUTH_SERVICE (auth_service),
                 "Failed to initialize the AuthService.");

    signon_auth_service_query_mechanisms (auth_service,
                                          "sasl",
                                          (SignonQueryMechanismCb)signon_query_mechanisms_cb,
                                          "Hello");
    if(!main_loop)
        main_loop = g_main_loop_new (NULL, FALSE);

    g_main_loop_run (main_loop);
    end_test ();
}
END_TEST


static gboolean
test_quit_main_loop_cb (gpointer data)
{
    g_main_loop_quit (main_loop);
    return FALSE;
}

static void
test_auth_session_query_mechanisms_cb (SignonAuthSession *self,
                                      gchar **mechanisms,
                                      const GError *error,
                                      gpointer user_data)
{
    if (error)
    {
        g_warning ("%s: %s", G_STRFUNC, error->message);
        g_main_loop_quit (main_loop);
        fail();
    }

    fail_unless (mechanisms != NULL, "The mechanisms does not exist");

    gchar** patterns = (gchar**)user_data;

    int i = g_strv_length(mechanisms);
    fail_unless( i == g_strv_length(patterns), "The number of obtained methods is wrong: %d %s", i);

    while ( i > 0 )
    {
        gchar* pattern = patterns[--i];
        fail_unless(g_strcmp0(pattern, mechanisms[i]) == 0, "The obtained mechanism differs from predefined pattern: %s vs %s", mechanisms[i], pattern);
    }

    g_strfreev(mechanisms);
    g_main_loop_quit (main_loop);
}

START_TEST(test_auth_session_query_mechanisms)
{
    g_type_init();

    GError *err = NULL;

    SignonIdentity *idty = signon_identity_new();
    fail_unless (idty != NULL, "Cannot create Iddentity object");

    SignonAuthSession *auth_session = signon_identity_create_session(idty,
                                                                     "ssotest",
                                                                     NULL,
                                                                     NULL,
                                                                     &err);
    fail_unless (auth_session != NULL, "Cannot create AuthSession object");

    g_clear_error(&err);

    gchar* patterns[4];
    patterns[0] = g_strdup("mech1");
    patterns[1] = g_strdup("mech2");
    patterns[2] = g_strdup("mech3");
    patterns[3] = NULL;

    signon_auth_session_query_available_mechanisms(auth_session,
                                                  (const gchar**)patterns,
                                                  test_auth_session_query_mechanisms_cb,
                                                  (gpointer)patterns);
    if(!main_loop)
        main_loop = g_main_loop_new (NULL, FALSE);

    g_main_loop_run (main_loop);

    g_free(patterns[2]);
    patterns[2] = NULL;

    signon_auth_session_query_available_mechanisms(auth_session,
                                                  (const gchar**)patterns,
                                                  test_auth_session_query_mechanisms_cb,
                                                  (gpointer)patterns);

    g_main_loop_run (main_loop);

    g_free(patterns[1]);
    patterns[1] = NULL;

    signon_auth_session_query_available_mechanisms(auth_session,
                                                  (const gchar**)patterns,
                                                  test_auth_session_query_mechanisms_cb,
                                                  (gpointer)patterns);

    g_main_loop_run (main_loop);

    g_free(patterns[0]);
    g_object_unref(idty);

    end_test ();
}
END_TEST

static void
test_auth_session_query_mechanisms_nonexisting_cb (SignonAuthSession *self,
                                                  gchar **mechanisms,
                                                  const GError *error,
                                                  gpointer user_data)
{
    if (!error)
    {
        g_main_loop_quit (main_loop);
        fail();
        return;
    }

    g_warning ("%s: %s", G_STRFUNC, error->message);
    g_main_loop_quit (main_loop);
}

START_TEST(test_auth_session_query_mechanisms_nonexisting)
{
    g_type_init();
    GError *err = NULL;

    SignonIdentity *idty = signon_identity_new();
    fail_unless (idty != NULL, "Cannot create Iddentity object");

    SignonAuthSession *auth_session = signon_identity_create_session(idty,
                                                                     "nonexisting",
                                                                     NULL,
                                                                     NULL,
                                                                     &err);

    fail_unless (auth_session != NULL, "Cannot create AuthSession object");

    g_clear_error(&err);

    gchar* patterns[4];
    patterns[0] = g_strdup("mech1");
    patterns[1] = g_strdup("mech2");
    patterns[2] = g_strdup("mech3");
    patterns[3] = NULL;

    signon_auth_session_query_available_mechanisms(auth_session,
                                                  (const gchar**)patterns,
                                                  test_auth_session_query_mechanisms_nonexisting_cb,
                                                  (gpointer)patterns);
    if(!main_loop)
        main_loop = g_main_loop_new (NULL, FALSE);

    g_main_loop_run (main_loop);

    g_free(patterns[0]);
    g_object_unref(idty);

    end_test ();
}
END_TEST

static void
test_auth_session_states_cb (SignonAuthSession *self,
                             gint state,
                             gchar *message,
                             gpointer user_data)
{
    gint *state_counter = (gint *)user_data;
    (*state_counter)++;
}

static void
test_auth_session_process_cb (SignonAuthSession *self,
                             GHashTable *sessionData,
                             const GError *error,
                             gpointer user_data)
{
    if (error)
    {
        g_warning ("%s: %s", G_STRFUNC, error->message);
        g_main_loop_quit (main_loop);
        fail();
    }

    fail_unless (sessionData != NULL, "The result is empty");

    gchar* usernameKey = g_strdup(SIGNON_SESSION_DATA_USERNAME);
    GValue* usernameVa = (GValue*)g_hash_table_lookup(sessionData, usernameKey);

    gchar* realmKey = g_strdup(SIGNON_SESSION_DATA_REALM);
    GValue* realmVa = (GValue*)g_hash_table_lookup(sessionData, realmKey);

    fail_unless(g_strcmp0(g_value_get_string(usernameVa), "test_username") == 0, "Wrong value of username");
    fail_unless(g_strcmp0(g_value_get_string(realmVa), "testRealm_after_test") == 0, "Wrong value of realm");

    g_hash_table_destroy(sessionData);

    g_free(usernameKey);
    g_free(realmKey);

    g_main_loop_quit (main_loop);
}

START_TEST(test_auth_session_creation)
{
    g_type_init();
    gint state_counter = 0;
    GError *err = NULL;

    SignonIdentity *idty = signon_identity_new();
    fail_unless (idty != NULL, "Cannot create Iddentity object");

    SignonAuthSession *auth_session = signon_identity_create_session(idty,
                                                                    "ssotest",
                                                                    test_auth_session_states_cb,
                                                                    &state_counter,
                                                                    &err);

    fail_unless (auth_session != NULL, "Cannot create AuthSession object");

    g_object_unref (idty);
    fail_unless (SIGNON_IS_IDENTITY(idty), "Identity must stay untill all its session are not destroyed");
    g_object_unref (auth_session);

    fail_if (SIGNON_IS_AUTH_SESSION(auth_session), "AuthSession is not synchronized with parent Identity");
    fail_if (SIGNON_IS_IDENTITY(idty), "Identity is not synchronized with its AuthSession");

    g_clear_error(&err);
}
END_TEST

START_TEST(test_auth_session_process)
{
    g_type_init();
    gint state_counter = 0;
    GError *err = NULL;

    SignonIdentity *idty = signon_identity_new();
    fail_unless (idty != NULL, "Cannot create Iddentity object");

    SignonAuthSession *auth_session = signon_identity_create_session(idty,
                                                                     "ssotest",
                                                                     test_auth_session_states_cb,
                                                                     &state_counter,
                                                                     &err);

    fail_unless (auth_session != NULL, "Cannot create AuthSession object");

    g_clear_error(&err);

    GHashTable* sessionData = g_hash_table_new(g_str_hash,
                                               g_str_equal);
    GValue* usernameVa = g_new0(GValue, 1);
    gchar* usernameKey = g_strdup(SIGNON_SESSION_DATA_USERNAME);
    g_value_init (usernameVa, G_TYPE_STRING);
    g_value_set_static_string(usernameVa, "test_username");

    g_hash_table_insert (sessionData,
                         usernameKey,
                         usernameVa);

    GValue* passwordVa = g_new0(GValue, 1);
    gchar* passwordKey = g_strdup(SIGNON_SESSION_DATA_SECRET);

    g_value_init (passwordVa, G_TYPE_STRING);
    g_value_set_static_string(passwordVa, "test_username");

    g_hash_table_insert (sessionData,
                         passwordKey,
                         passwordVa);

    signon_auth_session_process(auth_session,
                               sessionData,
                               "mech1",
                               test_auth_session_process_cb,
                               sessionData);
    if(!main_loop)
        main_loop = g_main_loop_new (NULL, FALSE);


    g_main_loop_run (main_loop);
    fail_unless (state_counter == 12, "Wrong numer of state change signals: %d", state_counter);
    state_counter = 0;

    signon_auth_session_process(auth_session,
                               sessionData,
                               "mech1",
                               test_auth_session_process_cb,
                               sessionData);

    g_main_loop_run (main_loop);
    fail_unless (state_counter == 12, "Wrong numer of state change signals: %d", state_counter);
    state_counter = 0;

    signon_auth_session_process(auth_session,
                               sessionData,
                               "mech1",
                               test_auth_session_process_cb,
                               sessionData);

    g_main_loop_run (main_loop);
    fail_unless (state_counter == 12, "Wrong numer of state change signals: %d", state_counter);
    state_counter = 0;

    g_object_unref (auth_session);
    g_object_unref (idty);

    g_value_unset(usernameVa);
    g_free(usernameVa);
    g_free(usernameKey);

    g_value_unset(passwordVa);
    g_free(passwordVa);
    g_free(passwordKey);


}
END_TEST

static guint
new_identity()
{
    DBusGConnection *connection;
    DBusGProxy *proxy;
    guint id = 0;
    GError *error = NULL;

    connection = dbus_g_bus_get (DBUS_BUS_SESSION, &error);

    if(connection)
    {
        proxy = dbus_g_proxy_new_for_name (connection,
                                           "com.nokia.singlesignon",
                                           "/SignonDaemon",
                                           "com.nokia.singlesignon.SignonDaemon");
    }
    else if (error)
    {
        g_warning ("%s %d returned error: %s", G_STRFUNC, __LINE__, error->message);
        g_error_free (error);
    }

    gchar *objectPath;
    com_nokia_singlesignon_SignonDaemon_register_new_identity (proxy, &objectPath, &error);

    if (error)
    {
        g_warning ("%s %d returned error: %s", G_STRFUNC, __LINE__, error->message);
        g_error_free (error);
        fail();
    }

    GHashTable *hash_table;
    gchar *key = "key";
    GValue value = {0};

    g_type_init ();
    g_value_init (&value, G_TYPE_STRING);
    g_value_set_static_string (&value, "value");

    hash_table = g_hash_table_new (g_str_hash, g_str_equal);
    g_hash_table_insert (hash_table, g_strdup(key),&value);

    proxy = dbus_g_proxy_new_for_name (connection,
                                       "com.nokia.singlesignon",
                                       objectPath,
                                       "com.nokia.singlesignon.SignonIdentity");

    com_nokia_singlesignon_SignonIdentity_store_credentials (proxy,
                                                             0,
                                                             "James Bond",
                                                             "007",
                                                             1,
                                                             hash_table,
                                                             "caption",
                                                             NULL,
                                                             NULL,
                                                             0,
                                                             &id,
                                                             &error);

    if(error)
    {
        g_warning ("%s %d: %s", G_STRFUNC, __LINE__, error->message);
        fail();
    }

    return id;

}

static gboolean
identity_registered_cb (gpointer data)
{
    g_main_loop_quit (main_loop);
    return FALSE;
}

START_TEST(test_get_existing_identity)
{
    g_type_init ();

    guint id = new_identity();

    fail_unless (id != 0);

    identity = signon_identity_new_from_db(id);

    fail_unless (identity != NULL);
    fail_unless (SIGNON_IS_IDENTITY (identity),
                 "Failed to initialize the Identity.");

    g_timeout_add (1000, identity_registered_cb, identity);
    main_loop = g_main_loop_new (NULL, FALSE);
    g_main_loop_run (main_loop);

    gchar *user_name;
    user_name = signon_identity_get_username(identity);
    fail_unless (g_strcmp0 (user_name, "James Bond") == 0);

    g_free (user_name);
    end_test ();
}
END_TEST

START_TEST(test_get_nonexisting_identity)
{
    g_type_init ();

    identity = signon_identity_new_from_db(G_MAXINT);

    fail_unless (identity != NULL);
    fail_unless (SIGNON_IS_IDENTITY (identity),
                 "Failed to initialize the Identity.");

    g_timeout_add (1000, identity_registered_cb, identity);
    main_loop = g_main_loop_new (NULL, FALSE);
    g_main_loop_run (main_loop);

    GError *error = NULL;
    error = signon_identity_get_last_error(identity);
    fail_unless (error != NULL);

    GQuark domain = error->domain;
    const char *domain_name = g_quark_to_string (domain);

    fail_unless (error->domain == SIGNON_ERROR);
    fail_unless (error->code == SIGNON_ERROR_NOT_FOUND);

    end_test ();
}
END_TEST

static void store_credentials_identity_cb(SignonIdentity *self,
                                         guint32 id,
                                         const GError *error,
                                         gpointer user_data)
{
    if(error)
    {
        g_warning ("%s %d: %s", G_STRFUNC, __LINE__, error->message);
        fail();
    }

    gint *last_id = (gint *)user_data;

    g_warning ("%s (prev_id vs new_id): %d vs %d", G_STRFUNC, *last_id, id);

    fail_unless (id > 0);
    fail_unless (id == (*last_id) + 1);

    (*last_id) += 1;

    g_main_loop_quit (main_loop);
}

START_TEST(test_store_credentials_identity)
{
    g_type_init ();
    SignonIdentity *idty = signon_identity_new();
    fail_unless (idty != NULL);
    fail_unless (SIGNON_IS_IDENTITY (idty),
                 "Failed to initialize the Identity.");

    GHashTable *methods;
    gchar *key = "key";
    GValue value = {0};

    g_type_init ();
    g_value_init (&value, G_TYPE_STRING);
    g_value_set_static_string (&value, "value");

    methods = g_hash_table_new (g_str_hash, g_str_equal);
    g_hash_table_insert (methods, g_strdup(key),&value);

    gint last_id = new_identity();

    signon_identity_store_credentials_with_args (idty,
                                                 "James Bond",
                                                 "007",
                                                 1,
                                                 methods,
                                                 "caption",
                                                 NULL,
                                                 NULL,
                                                 0,
                                                 store_credentials_identity_cb,
                                                 &last_id);

    g_timeout_add (1000, test_quit_main_loop_cb, idty);
    main_loop = g_main_loop_new (NULL, FALSE);
    g_main_loop_run (main_loop);

    gchar *user_name = signon_identity_get_username(idty);
    fail_unless (g_strcmp0 (user_name, "James Bond") == 0);

    g_free (user_name);
    g_object_unref(idty);
    end_test ();
}
END_TEST

Suite *
signon_suite(void)
{
    Suite *s = suite_create ("signon-glib");

    /* Core test case */
    TCase * tc_core = tcase_create("Core");
    tcase_set_timeout(tc_core, 10);
    tcase_add_test (tc_core, test_init);
    tcase_add_test (tc_core, test_query_methods);
    tcase_add_test (tc_core, test_query_mechanisms);
    tcase_add_test (tc_core, test_get_existing_identity);
    tcase_add_test (tc_core, test_get_nonexisting_identity);

    tcase_add_test (tc_core, test_auth_session_creation);
    tcase_add_test (tc_core, test_auth_session_query_mechanisms);
    tcase_add_test (tc_core, test_auth_session_query_mechanisms_nonexisting);
    tcase_add_test (tc_core, test_auth_session_process);
    tcase_add_test (tc_core, test_store_credentials_identity);

    suite_add_tcase (s, tc_core);

    return s;
}

int main(void)
{
    int number_failed;
    Suite * s = signon_suite();
    SRunner * sr = srunner_create(s);

    srunner_set_xml(sr, "/tmp/result.xml");
    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free (sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

/* vim: set ai et tw=75 ts=4 sw=4: */

