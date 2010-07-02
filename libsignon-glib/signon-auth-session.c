/* vi: set et sw=4 ts=4 cino=t0,(0: */
/* -*- Mode: C; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*
 * This file is part of libsignon-glib
 *
 * Copyright (C) 2009-2010 Nokia Corporation.
 *
 * Contact: Alberto Mardegan <alberto.mardegan@nokia.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * version 2.1 as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */

#include "signon-internals.h"
#include "signon-auth-session.h"
#include "signon-dbus-queue.h"
#include "signon-client-glib-gen.h"
#include "signon-auth-session-client-glib-gen.h"
#include "signon-marshal.h"
#include "signon-proxy.h"
#include "signon-utils.h"

G_DEFINE_TYPE (SignonAuthSession, signon_auth_session, G_TYPE_OBJECT);

/* Signals */
enum
{
    STATE_CHANGED,

    LAST_SIGNAL
};

static guint auth_session_signals[LAST_SIGNAL] = { 0 };
static gchar auth_session_process_pending_message[] = "The request is added to queue.";

struct _SignonAuthSessionPrivate
{
    DBusGProxy *proxy;
    SignonProxy *signon_proxy;

    gint id;
    gchar *method_name;

    gboolean busy;
    gboolean canceled;
    gboolean dispose_has_run;
};

typedef struct _AuthSessionQueryAvailableMechanismsData
{
    gchar **wanted_mechanisms;
    gpointer cb_data;
} AuthSessionQueryAvailableMechanismsData;

typedef struct _AuthSessionProcessData
{
    GHashTable *session_data;
    gchar *mechanism;
    gpointer cb_data;
} AuthSessionProcessData;

typedef struct _AuthSessionQueryAvailableMechanismsCbData
{
    SignonAuthSession *self;
    SignonAuthSessionQueryAvailableMechanismsCb cb;
    gpointer user_data;
} AuthSessionQueryAvailableMechanismsCbData;

typedef struct _AuthSessionProcessCbData
{
    SignonAuthSession *self;
    SignonAuthSessionProcessCb cb;
    gpointer user_data;
} AuthSessionProcessCbData;

#define SIGNON_AUTH_SESSION_PRIV(obj) (SIGNON_AUTH_SESSION(obj)->priv)
#define SIGNON_AUTH_SESSION_GET_PRIV(obj) (G_TYPE_INSTANCE_GET_PRIVATE ((obj), SIGNON_TYPE_AUTH_SESSION, SignonAuthSessionPrivate))


//TODO: remove with implementing normal error management
#define SSO_AUTH_SESSION_CONNECTION_PROBLEM_G \
    "Cannot create remote AuthSession object: check the signon daemon and authentication plugin."
#define SSO_AUTH_SESSION_BUSY_PROBLEM_G \
    "AuthSession: client is busy."
#define SSO_AUTH_SESSION_CANCELED_PROBLEM_G \
    "Challenge was canceled"

static void auth_session_state_changed_cb (DBusGProxy *proxy, gint state, gchar *message, gpointer user_data);
static void auth_session_remote_object_destroyed_cb (DBusGProxy *proxy, gpointer user_data);

static gboolean auth_session_priv_init (SignonAuthSession *self, guint id, const gchar *method_name, GError **err);
static void auth_session_get_object_path_reply (DBusGProxy *proxy, char * object_path, GError *error, gpointer userdata);

static void auth_session_set_id_ready_cb (gpointer object, const GError *error, gpointer user_data);
static void auth_session_query_available_mechanisms_ready_cb (gpointer object, const GError *error, gpointer user_data);
static void auth_session_process_ready_cb (gpointer object, const GError *error, gpointer user_data);
static void auth_session_cancel_ready_cb (gpointer object, const GError *error, gpointer user_data);

static void auth_session_query_mechanisms_reply (DBusGProxy *proxy, char **object_path, GError *error, gpointer userdata);
static void auth_session_process_reply (DBusGProxy *proxy, GHashTable *object_path, GError *error, gpointer userdata);

static void auth_session_check_remote_object(SignonAuthSession *self);

static GQuark
auth_session_errors_quark ()
{
  static GQuark quark = 0;

  if (!quark)
    quark = g_quark_from_static_string ("com.nokia.singlesignon.AuthSession.Errors");

  return quark;
}

static GQuark
auth_session_object_quark ()
{
  static GQuark quark = 0;

  if (!quark)
    quark = g_quark_from_static_string ("auth_session_object_quark");

  return quark;
}

static void
signon_auth_session_init (SignonAuthSession *self)
{
    self->priv = SIGNON_AUTH_SESSION_GET_PRIV (self);
    self->priv->signon_proxy = signon_proxy_new ();
}

static void
signon_auth_session_dispose (GObject *object)
{
    g_return_if_fail (SIGNON_IS_AUTH_SESSION (object));
    SignonAuthSession *self = SIGNON_AUTH_SESSION (object);
    SignonAuthSessionPrivate *priv = self->priv;
    g_return_if_fail (priv != NULL);

    if (priv->dispose_has_run)
        return;

    GError *err = NULL;

    if (priv->proxy)
    {
        com_nokia_singlesignon_SignonAuthSession_object_unref (priv->proxy, &err);
        g_object_unref (priv->proxy);
        priv->proxy = NULL;
    }

    if (priv->signon_proxy)
    {
        g_object_unref (priv->signon_proxy);
        priv->signon_proxy = NULL;
    }

    G_OBJECT_CLASS (signon_auth_session_parent_class)->dispose (object);

    priv->dispose_has_run = TRUE;
}

static void
signon_auth_session_finalize (GObject *object)
{
    g_return_if_fail (SIGNON_IS_AUTH_SESSION(object));

    SignonAuthSession *self = SIGNON_AUTH_SESSION(object);
    SignonAuthSessionPrivate *priv = self->priv;
    g_return_if_fail (priv != NULL);

    g_free (priv->method_name);

    G_OBJECT_CLASS (signon_auth_session_parent_class)->finalize (object);
}

static void
signon_auth_session_class_init (SignonAuthSessionClass *klass)
{
    GObjectClass *object_class = G_OBJECT_CLASS (klass);

    g_type_class_add_private (object_class, sizeof (SignonAuthSessionPrivate));

    auth_session_signals[STATE_CHANGED] =
            g_signal_new ("state-changed",
                          G_TYPE_FROM_CLASS (klass),
                          G_SIGNAL_RUN_LAST | G_SIGNAL_ACTION,
                          0,
                          NULL,
                          NULL,
                          signon_marshal_VOID__INT_STRING,
                          G_TYPE_NONE, 2,
                          G_TYPE_INT,
                          G_TYPE_STRING);

    object_class->dispose = signon_auth_session_dispose;
    object_class->finalize = signon_auth_session_finalize;
}

SignonAuthSession *
signon_auth_session_new (gint id,
                         const gchar *method_name,
                         GError **err)
{
    SignonAuthSession *self = SIGNON_AUTH_SESSION(g_object_new (SIGNON_TYPE_AUTH_SESSION, NULL));
    g_return_val_if_fail (self != NULL, NULL);

    if (!auth_session_priv_init(self, id, method_name, err))
    {
        if (*err)
            g_warning ("%s returned error: %s", G_STRFUNC, (*err)->message);

        g_object_unref (self);
        return NULL;
    }

    return self;
}

static void
auth_session_set_id_ready_cb (gpointer object,
                              const GError *error,
                              gpointer user_data)
{
    if (error)
    {
        g_warning ("%s returned error: %s", G_STRFUNC, error->message);
        return;
    }

    g_return_if_fail (SIGNON_IS_AUTH_SESSION (object));
    SignonAuthSession *self = SIGNON_AUTH_SESSION (object);
    SignonAuthSessionPrivate *priv = self->priv;
    g_return_if_fail (priv != NULL);

    gint id = GPOINTER_TO_INT(user_data);

    GError *err = NULL;
    com_nokia_singlesignon_SignonAuthSession_set_id (priv->proxy,
                                                     id,
                                                     &err);
    priv->id = id;

    if (err)
        g_warning ("%s returned error: %s", G_STRFUNC, err->message);

    g_clear_error(&err);
}

void
signon_auth_session_set_id(SignonAuthSession* self,
                           gint id)
{
    g_return_if_fail (SIGNON_IS_AUTH_SESSION (self));

    SignonAuthSessionPrivate *priv = self->priv;
    g_return_if_fail (priv != NULL);
    g_return_if_fail (id >= 0);

    auth_session_check_remote_object(self);
    _signon_object_call_when_ready (self,
                                    auth_session_object_quark(),
                                    auth_session_set_id_ready_cb,
                                    GINT_TO_POINTER(id));
}

const gchar *
signon_auth_session_get_method (SignonAuthSession *self)
{
    g_return_val_if_fail (SIGNON_IS_AUTH_SESSION (self), NULL);
    SignonAuthSessionPrivate *priv = self->priv;

    g_return_val_if_fail (priv != NULL, NULL);

    return priv->method_name;
}

void
signon_auth_session_query_available_mechanisms (SignonAuthSession *self,
                                                const gchar **wanted_mechanisms,
                                                SignonAuthSessionQueryAvailableMechanismsCb cb,
                                                gpointer user_data)
{
    g_return_if_fail (SIGNON_IS_AUTH_SESSION (self));
    SignonAuthSessionPrivate* priv = self->priv;

    g_return_if_fail (priv != NULL);

    AuthSessionQueryAvailableMechanismsCbData *cb_data = g_slice_new0 (AuthSessionQueryAvailableMechanismsCbData);
    cb_data->self = self;
    cb_data->cb = cb;
    cb_data->user_data = user_data;

    AuthSessionQueryAvailableMechanismsData *operation_data = g_slice_new0 (AuthSessionQueryAvailableMechanismsData);
    operation_data->wanted_mechanisms = g_strdupv ((gchar **)wanted_mechanisms);
    operation_data->cb_data = cb_data;

    auth_session_check_remote_object(self);
    _signon_object_call_when_ready (self,
                                    auth_session_object_quark(),
                                    auth_session_query_available_mechanisms_ready_cb,
                                    operation_data);
}

void
signon_auth_session_process (SignonAuthSession *self,
                             const GHashTable *session_data,
                             const gchar* mechanism,
                             SignonAuthSessionProcessCb cb,
                             gpointer user_data)
{
    g_return_if_fail (SIGNON_IS_AUTH_SESSION (self));
    SignonAuthSessionPrivate *priv = self->priv;

    g_return_if_fail (priv != NULL);
    g_return_if_fail (session_data != NULL);

    AuthSessionProcessCbData *cb_data = g_slice_new0 (AuthSessionProcessCbData);
    cb_data->self = self;
    cb_data->cb = cb;
    cb_data->user_data = user_data;

    AuthSessionProcessData *operation_data = g_slice_new0 (AuthSessionProcessData);

    operation_data->session_data = signon_copy_variant_map (session_data);
    operation_data->mechanism = g_strdup (mechanism);
    operation_data->cb_data = cb_data;

    priv->busy = TRUE;

    auth_session_check_remote_object(self);
    _signon_object_call_when_ready (self,
                                    auth_session_object_quark(),
                                    auth_session_process_ready_cb,
                                    operation_data);
}

void
signon_auth_session_cancel (SignonAuthSession *self)
{
    g_return_if_fail (SIGNON_IS_AUTH_SESSION (self));
    SignonAuthSessionPrivate *priv = self->priv;

    g_return_if_fail (priv != NULL);

    auth_session_check_remote_object(self);

    if (!priv->busy)
        return;

    priv->canceled = TRUE;
    _signon_object_call_when_ready (self,
                                    auth_session_object_quark(),
                                    auth_session_cancel_ready_cb,
                                    NULL);
}

static void
auth_session_get_object_path_reply (DBusGProxy *proxy, char * object_path,
                                    GError *error, gpointer userdata)
{
    g_return_if_fail (SIGNON_IS_AUTH_SESSION (userdata));
    SignonAuthSession *self = SIGNON_AUTH_SESSION (userdata);
    SignonAuthSessionPrivate *priv = self->priv;
    g_return_if_fail (priv != NULL);

    if (!g_strcmp0(object_path, "") || error)
    {
        if (error)
            DEBUG ("Error message is %s", error->message);
        else
            error = g_error_new (auth_session_errors_quark(), 1, SSO_AUTH_SESSION_CONNECTION_PROBLEM_G);
    }
    else
    {
        priv->proxy = dbus_g_proxy_new_from_proxy (DBUS_G_PROXY (priv->signon_proxy),
                                                   SIGNOND_AUTH_SESSION_INTERFACE,
                                                   object_path);

        dbus_g_object_register_marshaller (signon_marshal_VOID__INT_STRING,
                                           G_TYPE_NONE,
                                           G_TYPE_INT,
                                           G_TYPE_STRING,
                                           G_TYPE_INVALID);

        dbus_g_proxy_add_signal (priv->proxy,
                                 "stateChanged",
                                 G_TYPE_INT,
                                 G_TYPE_STRING,
                                 G_TYPE_INVALID);

        dbus_g_proxy_connect_signal (priv->proxy,
                                     "stateChanged",
                                     G_CALLBACK (auth_session_state_changed_cb),
                                     self,
                                     NULL);

        dbus_g_object_register_marshaller (g_cclosure_marshal_VOID__VOID,
                                           G_TYPE_NONE,
                                           G_TYPE_INVALID);

        dbus_g_proxy_add_signal (priv->proxy,
                                 "unregistered",
                                 G_TYPE_INVALID);

        dbus_g_proxy_connect_signal (priv->proxy,
                                     "unregistered",
                                     G_CALLBACK (auth_session_remote_object_destroyed_cb),
                                     self,
                                     NULL);
    }

    DEBUG ("Object path received: %s", object_path);
    _signon_object_ready (self, auth_session_object_quark (), error);
    g_clear_error (&error);
}

static void
auth_session_state_changed_cb (DBusGProxy *proxy,
                               gint state,
                               gchar *message,
                               gpointer user_data)
{
    g_return_if_fail (SIGNON_IS_AUTH_SESSION (user_data));
    SignonAuthSession *self = SIGNON_AUTH_SESSION (user_data);

    g_signal_emit ((GObject *)self,
                    auth_session_signals[STATE_CHANGED],
                    0,
                    state,
                    message);
}

static void auth_session_remote_object_destroyed_cb (DBusGProxy *proxy,
                                                     gpointer user_data)
{
    g_return_if_fail (SIGNON_IS_AUTH_SESSION (user_data));
    SignonAuthSession *self = SIGNON_AUTH_SESSION (user_data);
    SignonAuthSessionPrivate *priv = self->priv;
    g_return_if_fail (priv != NULL);
    DEBUG ("remote object unregistered");

    if (priv->proxy)
    {
        g_object_unref (priv->proxy);
        priv->proxy = NULL;
    }

    /*
     * as remote object is destroyed only
     * when the session core is destroyed,
     * so there should not be any processes
     * running
     * */
    priv->busy = FALSE;
    priv->canceled = FALSE;
    _signon_object_not_ready(self);
}

static gboolean
auth_session_priv_init (SignonAuthSession *self, guint id,
                        const gchar *method_name, GError **err)
{
    g_return_val_if_fail (SIGNON_IS_AUTH_SESSION (self), FALSE);
    SignonAuthSessionPrivate *priv = SIGNON_AUTH_SESSION_PRIV (self);
    g_return_val_if_fail (priv, FALSE);

    priv->id = id;
    priv->method_name = g_strdup (method_name);

    (void)com_nokia_singlesignon_SignonDaemon_get_auth_session_object_path_async (DBUS_G_PROXY (priv->signon_proxy),
                                                                                  (const guint)id,
                                                                                  method_name,
                                                                                  auth_session_get_object_path_reply,
                                                                                  self);
    priv->busy = FALSE;
    priv->canceled = FALSE;
    return TRUE;
}

static void
auth_session_query_mechanisms_reply (DBusGProxy *proxy, char **object_path,
                                     GError *error, gpointer userdata)
{
    GError *new_error = NULL;
    AuthSessionQueryAvailableMechanismsCbData *cb_data =
        (AuthSessionQueryAvailableMechanismsCbData *)userdata;
    g_return_if_fail (cb_data != NULL);

    if (error)
        new_error = _signon_errors_get_error_from_dbus (error);

    (cb_data->cb)
        (cb_data->self, object_path, new_error, cb_data->user_data);

    if (new_error)
        g_error_free (new_error);

    g_slice_free (AuthSessionQueryAvailableMechanismsCbData, cb_data);
}

static void
auth_session_process_reply (DBusGProxy *proxy, GHashTable *object_path,
                            GError *error, gpointer userdata)
{
    GError *new_error = NULL;
    AuthSessionProcessCbData *cb_data = (AuthSessionProcessCbData *)userdata;
    g_return_if_fail (cb_data != NULL);
    g_return_if_fail (cb_data->self != NULL);
    g_return_if_fail (cb_data->self->priv != NULL);

    if (error)
        new_error = _signon_errors_get_error_from_dbus (error);

    (cb_data->cb)
        (cb_data->self, object_path, new_error, cb_data->user_data);

    cb_data->self->priv->busy = FALSE;
    if (new_error)
        g_error_free (new_error);

    g_slice_free (AuthSessionProcessCbData, cb_data);
}

static void
auth_session_query_available_mechanisms_ready_cb (gpointer object, const GError *error,
                                                  gpointer user_data)
{
    g_return_if_fail (SIGNON_IS_AUTH_SESSION (object));
    SignonAuthSession *self = SIGNON_AUTH_SESSION (object);
    SignonAuthSessionPrivate *priv = self->priv;
    g_return_if_fail (priv != NULL);

    AuthSessionQueryAvailableMechanismsData *operation_data =
        (AuthSessionQueryAvailableMechanismsData *)user_data;
    g_return_if_fail (operation_data != NULL);

    AuthSessionQueryAvailableMechanismsCbData *cb_data = operation_data->cb_data;
    g_return_if_fail (cb_data != NULL);

    if (error)
    {
        (cb_data->cb)
            (self, NULL, error, cb_data->user_data);

        g_slice_free (AuthSessionQueryAvailableMechanismsCbData, cb_data);
    }
    else
    {
        g_return_if_fail (priv->proxy != NULL);
        (void) com_nokia_singlesignon_SignonAuthSession_query_available_mechanisms_async (
                    priv->proxy,
                    (const char **)operation_data->wanted_mechanisms,
                    auth_session_query_mechanisms_reply,
                    cb_data);

        g_signal_emit (self,
                       auth_session_signals[STATE_CHANGED],
                       0,
                       SIGNON_AUTH_SESSION_STATE_PROCESS_PENDING,
                       auth_session_process_pending_message);
    }

    g_strfreev (operation_data->wanted_mechanisms);
    g_slice_free (AuthSessionQueryAvailableMechanismsData, operation_data);
}

static void
auth_session_process_ready_cb (gpointer object, const GError *error, gpointer user_data)
{
    g_return_if_fail (SIGNON_IS_AUTH_SESSION (object));

    SignonAuthSession *self = SIGNON_AUTH_SESSION (object);
    SignonAuthSessionPrivate *priv = SIGNON_AUTH_SESSION_PRIV (self);

    AuthSessionProcessData *operation_data =
        (AuthSessionProcessData *)user_data;
    g_return_if_fail (operation_data != NULL);

    AuthSessionProcessCbData *cb_data = operation_data->cb_data;
    g_return_if_fail (cb_data != NULL);

    if (error || priv->canceled)
    {
        GError *err = ( error ? (GError *)error : g_error_new(auth_session_errors_quark(),
                                                              1,
                                                              SSO_AUTH_SESSION_CANCELED_PROBLEM_G) );

        DEBUG ("AuthSessionError: %s", err->message);

        (cb_data->cb)
            (self, operation_data->session_data, err, cb_data->user_data);

        if (!error)
            g_clear_error (&err);

        g_slice_free (AuthSessionProcessCbData, cb_data);

        priv->busy = FALSE;
        priv->canceled = FALSE;
    }
    else
    {
        g_return_if_fail (priv->proxy != NULL);

        (void)com_nokia_singlesignon_SignonAuthSession_process_async(
                    priv->proxy,
                    operation_data->session_data,
                    operation_data->mechanism,
                    auth_session_process_reply,
                    cb_data);

       g_hash_table_destroy (operation_data->session_data);

       g_signal_emit (self,
                       auth_session_signals[STATE_CHANGED],
                       0,
                       SIGNON_AUTH_SESSION_STATE_PROCESS_PENDING,
                       auth_session_process_pending_message);
    }

    g_free (operation_data->mechanism);
    g_slice_free (AuthSessionProcessData, operation_data);
}

static void
auth_session_cancel_ready_cb (gpointer object, const GError *error, gpointer user_data)
{
    g_return_if_fail (SIGNON_IS_AUTH_SESSION (object));
    g_return_if_fail (user_data == NULL);

    SignonAuthSession *self = SIGNON_AUTH_SESSION (object);
    SignonAuthSessionPrivate *priv = self->priv;
    g_return_if_fail (priv != NULL);

    if (error)
    {
        //TODO: in general this function does not return any values,
        // that is why I think it should not emit anything for this particular case
        DEBUG("error during initialization");
    }
    else if (priv->proxy && priv->busy)
        com_nokia_singlesignon_SignonAuthSession_cancel (priv->proxy, NULL);

    priv->busy = FALSE;
    priv->canceled = FALSE;
}

static void
auth_session_check_remote_object(SignonAuthSession *self)
{
    g_return_if_fail (self != NULL);
    SignonAuthSessionPrivate *priv = self->priv;
    g_return_if_fail (priv != NULL);

    if (priv->proxy != NULL)
        return;

    g_return_if_fail (priv->signon_proxy != NULL);

    (void)com_nokia_singlesignon_SignonDaemon_get_auth_session_object_path_async (DBUS_G_PROXY (priv->signon_proxy),
                                                                                  (const guint)priv->id,
                                                                                  priv->method_name,
                                                                                  auth_session_get_object_path_reply,
                                                                                  self);
}
