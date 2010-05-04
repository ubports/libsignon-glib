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

/**
 * SECTION:signon-identity
 * @title: SignonIdentity
 * @short_description: client side presentation of a credential.
 *
 * The #SignonIdentity represents an database entry for a single identity.
 */

#include "signon-identity.h"
#include "signon-auth-session.h"
#include "signon-internals.h"
#include "signon-proxy.h"
#include "signon-identity-glib-gen.h"
#include "signon-client-glib-gen.h"
#include "signon-dbus-queue.h"
#include "signon-utils.h"
#include "signon-errors.h"

#define SIGNON_IDENTITY_IFACE  "com.nokia.singlesignon.SignonIdentity"

G_DEFINE_TYPE (SignonIdentity, signon_identity, G_TYPE_OBJECT);

enum
{
    PROP_0,
    PROP_ID
};

typedef enum {
    NOT_READY,
    READY,
    REMOVED,
} IdentityState;

typedef enum  {
    DATA_UPDATED = 0,
    IDENTITY_REMOVED,
    IDENTITY_SIGNED_OUT
} RemoteIdentityState;

struct _SignonIdentityPrivate
{
    DBusGProxy *proxy;
    SignonProxy *signon_proxy;

    SignonIdentityInfo *identity_info;
    GError *last_error;

    GSList *sessions;

    IdentityState state;

    gboolean signed_out;
    gboolean updated;

    guint id;
};

enum {
    SIGNEDOUT_SIGNAL,
    LAST_SIGNAL
};

static guint signals[LAST_SIGNAL];

struct _SignonIdentityInfo
{
    gint id;
    gchar *username;
    gchar *secret;
    gchar *caption;
    gboolean store_secret;
    GHashTable *methods;
    gchar **realms;
    gchar **access_control_list;
    gint type;
};



#define SIGNON_IDENTITY_PRIV(obj) (SIGNON_IDENTITY(obj)->priv)

typedef struct _IdentityStoreCredentialsCbData
{
    SignonIdentity *self;
    SignonIdentityStoreCredentialsCb cb;
    gpointer user_data;
} IdentityStoreCredentialsCbData;

typedef struct _IdentityStoreCredentialsData
{
    gchar *username;
    gchar *secret;
    gboolean store_secret;
    GHashTable *methods;
    gchar *caption;
    gchar **realms;
    gchar **access_control_list;
    gint type;
    gpointer cb_data;
} IdentityStoreCredentialsData;

typedef enum {
    SIGNON_VERIFY_USER,
    SIGNON_VERIFY_SECRET,
    SIGNON_INFO,
    SIGNON_REMOVE,
    SIGNON_SIGNOUT
} IdentityOperation;

typedef struct _IdentityVerifyCbData
{
    SignonIdentity *self;
    SignonIdentityVerifyCb cb;
    gpointer user_data;
} IdentityVerifyCbData;

typedef struct _IdentityVerifyData
{
    gchar *data_to_send;
    IdentityOperation operation;
    gpointer cb_data;
} IdentityVerifyData;

typedef struct _IdentityInfoCbData
{
    SignonIdentity *self;
    SignonIdentityInfoCb cb;
    gpointer user_data;
} IdentityInfoCbData;

typedef struct _IdentityVoidCbData
{
    SignonIdentity *self;
    SignonIdentityVoidCb cb;
    gpointer user_data;
} IdentityVoidCbData;

typedef struct _IdentityVoidData
{
    IdentityOperation operation;
    gpointer cb_data;
} IdentityVoidData;

static void identity_registered (SignonIdentity *identity, DBusGProxy *proxy, char *object_path,
                                 GPtrArray *identity_array, GError *error);
static void identity_new_cb (DBusGProxy *proxy, char *objectPath, GError *error, gpointer userdata);
static void identity_new_from_db_cb (DBusGProxy *proxy, char *objectPath, GPtrArray *identityData,
                                      GError *error, gpointer userdata);
static void identity_store_credentials_ready_cb (gpointer object, const GError *error, gpointer user_data);
static void identity_store_credentials_reply (DBusGProxy *proxy, guint id, GError *error, gpointer userdata);
static void identity_session_object_destroyed_cb (gpointer data, GObject *where_the_session_was);
static void identity_verify_data (SignonIdentity *self, const gchar *data_to_send, gint operation,
                                    SignonIdentityVerifyCb cb, gpointer user_data);
static void identity_verify_ready_cb (gpointer object, const GError *error, gpointer user_data);
static void identity_verify_reply (DBusGProxy *proxy, gboolean valid, GError *error, gpointer userdata);

static void identity_signout_reply (DBusGProxy *proxy, gboolean result, GError *error, gpointer userdata);
static void identity_removed_reply (DBusGProxy *proxy, GError *error, gpointer userdata);
static void identity_info_reply(DBusGProxy *proxy, GPtrArray *identity_array,
                                    GError *error, gpointer userdata);
static void identity_remove_ready_cb (gpointer object, const GError *error, gpointer user_data);
static void identity_signout_ready_cb (gpointer object, const GError *error, gpointer user_data);
static void identity_info_ready_cb (gpointer object, const GError *error, gpointer user_data);
static void identity_state_changed_cb (DBusGProxy *proxy, gint state, gpointer user_data);

static SignonIdentityInfo *identity_ptrarray_to_identity_info (const GPtrArray *identity_array);

static void identity_process_signout (SignonIdentity *self);
static void identity_process_updated (SignonIdentity *self);
static void identity_process_removed (SignonIdentity *self);

static const gchar *identity_info_get_secret (const SignonIdentityInfo *info);
static void identity_info_set_id (SignonIdentityInfo *info, gint id);
static void identity_info_set_methods (SignonIdentityInfo *info, const GHashTable *methods);
static void identity_methods_copy (gpointer key, gpointer value, gpointer user_data);

static GHashTable *identity_methods_to_valuearray (const GHashTable *methods);

static GQuark
identity_object_quark ()
{
  static GQuark quark = 0;

  if (!quark)
    quark = g_quark_from_static_string ("identity_object_quark");

  return quark;
}

static void
signon_identity_set_property (GObject *object,
                              guint property_id,
                              const GValue *value,
                              GParamSpec *pspec)
{
    SignonIdentity *self = SIGNON_IDENTITY (object);

    switch (property_id)
    {
    case PROP_ID:
        self->priv->id = g_value_get_uint (value);
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
        break;
    }
}

static void
signon_identity_get_property (GObject *object,
                              guint property_id,
                              GValue *value,
                              GParamSpec *pspec)
{
    SignonIdentity *self = SIGNON_IDENTITY (object);

    switch (property_id)
    {
    case PROP_ID:
        g_value_set_uint (value, self->priv->id);
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
        break;
    }
}

static void
signon_identity_init (SignonIdentity *identity)
{
    identity->priv = G_TYPE_INSTANCE_GET_PRIVATE (identity,
                                                  SIGNON_TYPE_IDENTITY,
                                                  SignonIdentityPrivate);

    identity->priv->signon_proxy = signon_proxy_new();
}

static void
signon_identity_dispose (GObject *object)
{
    SignonIdentity *identity = SIGNON_IDENTITY (object);
    SignonIdentityPrivate *priv = identity->priv;

    if (priv->identity_info)
    {
        signon_identity_info_free (priv->identity_info);
        priv->identity_info = NULL;
    }

    if (priv->last_error)
        g_error_free (priv->last_error);

    if (priv->signon_proxy)
    {
        g_object_unref (priv->signon_proxy);
        priv->signon_proxy = NULL;
    }

    if (priv->proxy)
    {
        g_object_unref (priv->proxy);
        priv->proxy = NULL;
    }

    if (priv->sessions)
        g_critical ("SignonIdentity: the list of AuthSessions MUST be empty");

    G_OBJECT_CLASS (signon_identity_parent_class)->dispose (object);
}

static void
signon_identity_finalize (GObject *object)
{
    G_OBJECT_CLASS (signon_identity_parent_class)->finalize (object);
}

static void
signon_identity_class_init (SignonIdentityClass *klass)
{
    GObjectClass *object_class = G_OBJECT_CLASS (klass);
    GParamSpec *pspec;

    object_class->set_property = signon_identity_set_property;
    object_class->get_property = signon_identity_get_property;

    pspec = g_param_spec_uint ("id",
                               "Identity ID",
                               "Set/Get Identity ID",
                               0,
                               G_MAXUINT,
                               0,
                               G_PARAM_READWRITE);

    g_object_class_install_property (object_class,
                                     PROP_ID,
                                     pspec);

    g_type_class_add_private (object_class, sizeof (SignonIdentityPrivate));

    signals[SIGNEDOUT_SIGNAL] = g_signal_new("signon-identity-signout",
                                    G_TYPE_FROM_CLASS (klass),
                                    G_SIGNAL_RUN_LAST | G_SIGNAL_NO_RECURSE | G_SIGNAL_NO_HOOKS,
                                    0 /* class closure */,
                                    NULL /* accumulator */,
                                    NULL /* accu_data */,
                                    g_cclosure_marshal_VOID__VOID,
                                    G_TYPE_NONE /* return_type */,
                                    0);

    object_class->dispose = signon_identity_dispose;
    object_class->finalize = signon_identity_finalize;
}

static void
identity_state_changed_cb (DBusGProxy *proxy,
                           gint state,
                           gpointer user_data)
{
    g_return_if_fail (SIGNON_IS_IDENTITY (user_data));
    SignonIdentity *self = SIGNON_IDENTITY (user_data);

    switch (state) {
        case DATA_UPDATED:
            DEBUG ("State changed to DATA_UPDATED");
            identity_process_updated (self);
            break;
        case IDENTITY_REMOVED:
            DEBUG ("State changed to IDENTITY_REMOVED");
            identity_process_removed (self);
            break;
        case IDENTITY_SIGNED_OUT:
            DEBUG ("State changed to IDENTITY_SIGNED_OUT");
            identity_process_signout (self);
            break;
        default:
            g_critical ("wrong state value obtained from signon daemon");
    };
}

static void
identity_registered (SignonIdentity *identity, DBusGProxy *proxy,
                     char *object_path, GPtrArray *identity_array,
                     GError *error)
    {
    g_return_if_fail (SIGNON_IS_IDENTITY (identity));

    SignonIdentityPrivate *priv;
    priv = identity->priv;

    g_return_if_fail (priv != NULL);

    if (error)
    {
        g_warning ("%s: %s", G_STRFUNC, error->message);

        if (priv->last_error)
            g_error_free (priv->last_error);

        priv->last_error = error;
    }
    else
    {
        DEBUG("%s: %s", G_STRFUNC, object_path);
        /*
         * TODO: as Aurel will finalize the code polishing so we will
         * need to implement the refresh of the proxy to SignonIdentity
         * */
        g_return_if_fail (priv->proxy == NULL);

        priv->proxy = dbus_g_proxy_new_from_proxy (DBUS_G_PROXY (priv->signon_proxy),
                                                   SIGNON_IDENTITY_IFACE,
                                                   object_path);

        dbus_g_object_register_marshaller (g_cclosure_marshal_VOID__INT,
                                           G_TYPE_NONE,
                                           G_TYPE_INT,
                                           G_TYPE_INVALID);

        dbus_g_proxy_add_signal (priv->proxy,
                                 "infoUpdated",
                                 G_TYPE_INT,
                                 G_TYPE_INVALID);

        dbus_g_proxy_connect_signal (priv->proxy,
                                     "infoUpdated",
                                     G_CALLBACK (identity_state_changed_cb),
                                     identity,
                                     NULL);

        if (identity_array)
        {
            DEBUG("%s: ", G_STRFUNC);
            priv->identity_info = identity_ptrarray_to_identity_info (identity_array);
            g_ptr_array_free (identity_array, TRUE);
        }

        priv->updated = TRUE;
    }

    _signon_object_ready (identity, identity_object_quark (), error);
    identity->priv->state = READY;
}

GError*
signon_identity_get_last_error (SignonIdentity *identity)
{
    g_return_val_if_fail (SIGNON_IS_IDENTITY (identity), NULL);

    SignonIdentityPrivate *priv;
    priv = identity->priv;

    return priv->last_error;
}

static void
identity_new_cb (DBusGProxy *proxy,
                 char *object_path,
                 GError *error,
                 gpointer userdata)
{
    SignonIdentity *identity = (SignonIdentity*)userdata;
    g_return_if_fail (identity != NULL);
    DEBUG ("%s %d", G_STRFUNC, __LINE__);
    GError *new_error = _signon_errors_get_error_from_dbus (error);
    identity_registered (identity, proxy, object_path, NULL, new_error);
}

static void
identity_new_from_db_cb (DBusGProxy *proxy,
                         char *objectPath,
                         GPtrArray *identityData,
                         GError *error,
                         gpointer userdata)
{
    SignonIdentity *identity = (SignonIdentity*)userdata;
    g_return_if_fail (identity != NULL);
    DEBUG ("%s %d", G_STRFUNC, __LINE__);
    GError *new_error = _signon_errors_get_error_from_dbus (error);
    identity_registered (identity, proxy, objectPath, identityData, new_error);
}

/**
 * signon_identity_new_from_db:
 * @id: identity ID.
 *
 * Construct an identity object associated with an existing identity record.
 * Returns: an instance of an #SignonIdentity.
 */
SignonIdentity*
signon_identity_new_from_db (guint32 id)
{
    SignonIdentity *identity;
    DEBUG ("%s %d: %d\n", G_STRFUNC, __LINE__, id);
    if (id == 0)
        return NULL;

    identity = g_object_new (SIGNON_TYPE_IDENTITY, "id", id, NULL);
    g_return_val_if_fail (SIGNON_IS_IDENTITY (identity), NULL);
    g_return_val_if_fail (identity->priv != NULL, NULL);

    identity->priv->id = id;

    com_nokia_singlesignon_SignonDaemon_register_stored_identity_async
        (DBUS_G_PROXY (identity->priv->signon_proxy), id, identity_new_from_db_cb, identity);

    return identity;
}

/**
 * signon_identity_new
 * @id: identity ID.
 *
 * Construct an identity object associated with an existing identity record.
 * Returns: an instance of an #SignonIdentity.
 */
SignonIdentity*
signon_identity_new ()
{
    DEBUG ("%s %d", G_STRFUNC, __LINE__);
    SignonIdentity *identity = g_object_new (SIGNON_TYPE_IDENTITY, NULL);
    g_return_val_if_fail (SIGNON_IS_IDENTITY (identity), NULL);
    g_return_val_if_fail (identity->priv != NULL, NULL);

    com_nokia_singlesignon_SignonDaemon_register_new_identity_async
        (DBUS_G_PROXY (identity->priv->signon_proxy), identity_new_cb, identity);

    return identity;
}

static void
identity_session_object_destroyed_cb(gpointer data,
                                     GObject *where_the_session_was)
{
    g_return_if_fail (SIGNON_IS_IDENTITY (data));
    DEBUG ("%s %d", G_STRFUNC, __LINE__);

    SignonIdentity *self = SIGNON_IDENTITY (data);
    SignonIdentityPrivate *priv = self->priv;
    g_return_if_fail (priv != NULL);

    priv->sessions = g_slist_remove(priv->sessions, (gpointer)where_the_session_was);
    g_object_unref (self);
}

/**
 * §:
 * @self: self.
 * @method: method.
 * @user_data: user_data.
 * @cb: cb.
 * @user_data: user_data.
 * @error: error.
 *
 * Construct an identity object associated with an existing identity record.
 * Returns: an instance of an #SignonIdentity.
 */
SignonAuthSession *signon_identity_create_session(SignonIdentity *self,
                                                  const gchar *method,
                                                  SignonAuthSessionStateCahngedCb cb,
                                                  gpointer user_data,
                                                  GError **error)
{
    g_return_val_if_fail (SIGNON_IS_IDENTITY (self), NULL);

    SignonIdentityPrivate *priv = self->priv;
    g_return_val_if_fail (priv != NULL, NULL);

    DEBUG ("%s %d", G_STRFUNC, __LINE__);

    SignonAuthSession *session = signon_auth_session_new (priv->id,
                                                          method,
                                                          cb,
                                                          user_data,
                                                          error);
    if (session)
    {
        DEBUG ("%s %d", G_STRFUNC, __LINE__);
        priv->sessions = g_slist_append(priv->sessions, session);
        g_object_weak_ref (G_OBJECT(session),
                           identity_session_object_destroyed_cb,
                           self);
        /*
         * if you want to delete the identity
         * you MUST delete all authsessions
         * first
         * */
        g_object_ref (self);
        priv->signed_out = FALSE;
    }

    return session;
}

/**
 * signon_identity_store_credentials:
 * @id: identity ID.
 * @info: info.
 * @cb: callback
 * @user_data : user_data.
 *
 * Stores info for correspondent identity
 * Returns: result
 */
void signon_identity_store_credentials_with_info(SignonIdentity *self,
                                                 const SignonIdentityInfo *info,
                                                 SignonIdentityStoreCredentialsCb cb,
                                                 gpointer user_data)
{
    g_return_if_fail(info != NULL);

    signon_identity_store_credentials_with_args(self,
                                                info->username,
                                                info->secret,
                                                info->store_secret,
                                                info->methods,
                                                info->caption,
                                                (const gchar* const *)info->realms,
                                                (const gchar* const *)info->access_control_list,
                                                info->type,
                                                cb,
                                                user_data);
}




static GHashTable *
identity_methods_to_valuearray (const GHashTable *methods)
{
    DEBUG ("%s", __func__);
    GHashTable *valuearray = g_hash_table_new_full (g_str_hash, g_str_equal,
                                                g_free, (GDestroyNotify)signon_free_gvalue);
    g_hash_table_foreach ((GHashTable *)methods,
                            signon_stringarray_to_value, valuearray);
    return valuearray;
}

/**
 * signon_identity_store_credentials:
 * @id: identity ID.
 * @username: username.
 * @secret: secret.
 * @store_secret: store secret flag.
 * @methods: methods.
 * @caption: caption.
 * @realms: relams.
 * @access_control_list: access control list.
 * @cb: callback
 * @user_data : user_data.
 *
 * Stores the given identity into credentials DB
  */
void signon_identity_store_credentials_with_args(SignonIdentity *self,
                                                 const gchar *username,
                                                 const gchar *secret,
                                                 const gboolean store_secret,
                                                 const GHashTable *methods,
                                                 const gchar *caption,
                                                 const gchar* const *realms,
                                                 const gchar* const *access_control_list,
                                                 SignonIdentityType type,
                                                 SignonIdentityStoreCredentialsCb cb,
                                                 gpointer user_data)
{
    g_return_if_fail (SIGNON_IS_IDENTITY (self));

    SignonIdentityPrivate *priv = self->priv;
    g_return_if_fail (priv != NULL);

    g_return_if_fail (methods != NULL);

    DEBUG ("%s %d", G_STRFUNC, __LINE__);

    IdentityStoreCredentialsCbData *cb_data = g_slice_new0 (IdentityStoreCredentialsCbData);
    cb_data->self = self;
    cb_data->cb = cb;
    cb_data->user_data = user_data;

    IdentityStoreCredentialsData *operation_data = g_slice_new0 (IdentityStoreCredentialsData);

    operation_data->username = g_strdup (username);
    operation_data->secret = g_strdup (secret);
    operation_data->store_secret = store_secret;
    operation_data->methods = identity_methods_to_valuearray (methods);
    operation_data->caption = g_strdup (caption);
    operation_data->realms = g_strdupv((gchar **)realms);
    operation_data->access_control_list = g_strdupv((gchar **)access_control_list);
    operation_data->type = (gint)type;
    operation_data->cb_data = cb_data;

    _signon_object_call_when_ready (self,
                                    identity_object_quark(),
                                    identity_store_credentials_ready_cb,
                                    operation_data);
}

static void
identity_store_credentials_ready_cb (gpointer object, const GError *error, gpointer user_data)
{
    g_return_if_fail (SIGNON_IS_IDENTITY (object));

    SignonIdentity *self = SIGNON_IDENTITY (object);
    SignonIdentityPrivate *priv = self->priv;
    g_return_if_fail (priv != NULL);

    DEBUG ("%s %d", G_STRFUNC, __LINE__);

    IdentityStoreCredentialsData *operation_data =
        (IdentityStoreCredentialsData *)user_data;
    g_return_if_fail (operation_data != NULL);

    IdentityStoreCredentialsCbData *cb_data = operation_data->cb_data;
    g_return_if_fail (cb_data != NULL);

    if (error)
    {
        DEBUG ("IdentityError: %s", error->message);

        if (cb_data->cb)
        {
            (cb_data->cb) (self, 0, error, cb_data->user_data);
        }

        g_slice_free (IdentityStoreCredentialsCbData, cb_data);
    }
    else
    {
        g_return_if_fail (priv->proxy != NULL);

        (void)com_nokia_singlesignon_SignonIdentity_store_credentials_async(
                    priv->proxy,
                    priv->id,
                    operation_data->username,
                    operation_data->secret,
                    operation_data->store_secret,
                    operation_data->methods,
                    operation_data->caption,
                    (const char **)operation_data->realms,
                    (const char **)operation_data->access_control_list,
                    operation_data->type,
                    identity_store_credentials_reply,
                    cb_data);
    }

    g_free (operation_data->username);
    g_free (operation_data->secret);
    g_free (operation_data->caption);
    g_hash_table_destroy (operation_data->methods);
    g_strfreev (operation_data->realms);
    g_strfreev (operation_data->access_control_list);

    g_slice_free (IdentityStoreCredentialsData, operation_data);
}

static void
identity_store_credentials_reply (DBusGProxy *proxy,
                                  guint id,
                                  GError *error,
                                  gpointer userdata)
{
    GError *new_error = NULL;
    IdentityStoreCredentialsCbData *cb_data = (IdentityStoreCredentialsCbData *)userdata;

    g_return_if_fail (cb_data != NULL);
    g_return_if_fail (cb_data->self != NULL);
    g_return_if_fail (cb_data->self->priv != NULL);

    SignonIdentityPrivate *priv = cb_data->self->priv;

    new_error = _signon_errors_get_error_from_dbus (error);

    if (cb_data->cb)
    {
        (cb_data->cb) (cb_data->self, id, new_error, cb_data->user_data);
    }

    if (error == NULL)
    {
        g_return_if_fail (priv->identity_info == NULL);

        GSList *slist = priv->sessions;

        while (slist)
        {
            SignonAuthSession *session = SIGNON_AUTH_SESSION (priv->sessions->data);
            signon_auth_session_set_id (session, id);
            slist = g_slist_next (slist);
        }

        g_object_set (cb_data->self, "id", id, NULL);
        cb_data->self->priv->id = id;

        /*
         * if the previous state was REMOVED
         * then we need to reset it
         * */
        priv->state = READY;
    }

    g_clear_error(&new_error);
    g_slice_free (IdentityStoreCredentialsCbData, cb_data);
}

static void
identity_verify_reply (DBusGProxy *proxy,
                       gboolean valid,
                       GError *error,
                       gpointer userdata)
{
    GError *new_error = NULL;
    IdentityVerifyCbData *cb_data = (IdentityVerifyCbData *)userdata;

    g_return_if_fail (cb_data != NULL);
    g_return_if_fail (cb_data->self != NULL);

    new_error = _signon_errors_get_error_from_dbus (error);

    if (cb_data->cb)
    {
        (cb_data->cb) (cb_data->self, valid, new_error, cb_data->user_data);
    }

    g_clear_error(&new_error);
    g_slice_free (IdentityVerifyCbData, cb_data);
}

static void
identity_verify_ready_cb (gpointer object, const GError *error, gpointer user_data)
{
    g_return_if_fail (SIGNON_IS_IDENTITY (object));

    SignonIdentity *self = SIGNON_IDENTITY (object);
    SignonIdentityPrivate *priv = self->priv;
    g_return_if_fail (priv != NULL);

    DEBUG ("%s %d", G_STRFUNC, __LINE__);

    IdentityVerifyData *operation_data =
        (IdentityVerifyData *)user_data;
    g_return_if_fail (operation_data != NULL);

    IdentityVerifyCbData *cb_data = operation_data->cb_data;
    g_return_if_fail (cb_data != NULL);

    if (priv->state == REMOVED)
    {
        GError *new_error = g_error_new (signon_error_quark(),
                                         SIGNON_ERROR_NOT_FOUND,
                                         "Already removed from database.");

        if (cb_data->cb)
        {
            (cb_data->cb) (self, FALSE, new_error, cb_data->user_data);
        }

        g_error_free (new_error);
        g_slice_free (IdentityVerifyCbData, cb_data);
    }
    else if (error)
    {
        DEBUG ("IdentityError: %s", error->message);

        if (cb_data->cb)
        {
            (cb_data->cb) (self, FALSE, error, cb_data->user_data);
        }

        g_slice_free (IdentityVerifyCbData, cb_data);
    }
    else
    {
        DEBUG ("%s %d", G_STRFUNC, __LINE__);
        g_return_if_fail (priv->proxy != NULL);

        switch (operation_data->operation) {
            case SIGNON_VERIFY_SECRET:
                com_nokia_singlesignon_SignonIdentity_verify_secret_async(
                        priv->proxy,
                        operation_data->data_to_send,
                        identity_verify_reply,
                        cb_data);
            break;
            case SIGNON_VERIFY_USER:
            com_nokia_singlesignon_SignonIdentity_verify_user_async(
                    priv->proxy,
                    operation_data->data_to_send,
                    identity_verify_reply,
                    cb_data);
            break;
            default: g_critical ("Wrong operation code");
        };
    }

    g_free (operation_data->data_to_send);
    g_slice_free (IdentityVerifyData, operation_data);
}

static void
identity_verify_data(SignonIdentity *self,
                     const gchar *data_to_send,
                     gint operation,
                     SignonIdentityVerifyCb cb,
                     gpointer user_data)
{
    g_return_if_fail (SIGNON_IS_IDENTITY (self));

    SignonIdentityPrivate *priv = self->priv;
    g_return_if_fail (priv != NULL);

    DEBUG ("%s %d", G_STRFUNC, __LINE__);

    IdentityVerifyCbData *cb_data = g_slice_new0 (IdentityVerifyCbData);
    cb_data->self = self;
    cb_data->cb = cb;
    cb_data->user_data = user_data;

    IdentityVerifyData *operation_data = g_slice_new0 (IdentityVerifyData);

    operation_data->data_to_send = g_strdup (data_to_send);
    operation_data->operation = operation;
    operation_data->cb_data = cb_data;

    _signon_object_call_when_ready (self,
                                    identity_object_quark(),
                                    identity_verify_ready_cb,
                                    operation_data);
}

/**
 * sigon_identity_verify_user:
 * @message: message.
 * @cb: callback
 * @user_data : user_data.
 *
 * Verifies the given username
 * gboolean result: is verified or not
 */
void signon_identity_verify_user(SignonIdentity *self,
                                const gchar *message,
                                SignonIdentityVerifyCb cb,
                                gpointer user_data)
{
    identity_verify_data (self,
                          message,
                          SIGNON_VERIFY_USER,
                          cb,
                          user_data);
}

/**
 * sigon_identity_verify_secret:
 * @message: secret.
 * @cb: callback
 * @user_data : user_data.
 *
 * Verifies the given secret
 * gboolean result: is verified or not
 */
void signon_identity_verify_secret(SignonIdentity *self,
                                  const gchar *secret,
                                  SignonIdentityVerifyCb cb,
                                  gpointer user_data)
{
    identity_verify_data (self,
                          secret,
                          SIGNON_VERIFY_SECRET,
                          cb,
                          user_data);
}

static void
identity_value_to_stringarray (gpointer key, gpointer value, gpointer user_data)
{
    gchar **stringarray = (gchar **)g_value_get_boxed ((const GValue *)value);
    g_hash_table_insert ((GHashTable *)user_data, g_strdup((gchar *)key),
                            g_strdupv (stringarray));
}

static SignonIdentityInfo *
identity_ptrarray_to_identity_info (const GPtrArray *identity_array)
{
    if (!identity_array)
        return NULL;

    SignonIdentityInfo *info = signon_identity_info_new ();

    DEBUG("%s: ", G_STRFUNC);
    GValue *value;

    /* get the id (gint) */
    value = g_ptr_array_index (identity_array, 0);
    g_assert (G_VALUE_HOLDS_UINT(value));
    identity_info_set_id (info, g_value_get_uint (value));
    g_value_unset (value);

    /* get the user name (gchar*) */
    value = g_ptr_array_index (identity_array, 1);
    g_assert (G_VALUE_HOLDS_STRING(value));
    signon_identity_info_set_username (info, g_value_get_string (value));
    g_value_unset (value);

    /* get the password (gchar*)
     * TODO: fix it as soon
     * as reply from server will
     * be changed
     * */

    value = g_ptr_array_index (identity_array, 2);
    g_assert (G_VALUE_HOLDS_STRING(value));
    info->store_secret = (g_value_get_string (value) != NULL);
    g_value_unset (value);

    /* get the caption (gchar*) */
    value = g_ptr_array_index (identity_array, 3);
    g_assert (G_VALUE_HOLDS_STRING(value));
    signon_identity_info_set_caption (info, g_value_get_string (value));
    g_value_unset (value);

    /* get the realms (gchar**) */
    value = g_ptr_array_index (identity_array, 4);
    g_assert (G_VALUE_TYPE (value) == G_TYPE_STRV);
    signon_identity_info_set_realms (info, (const gchar* const *)g_value_get_boxed (value));
    g_value_unset (value);

    /* get the methods GPtrArray (QVariantMap in original) */
    value = g_ptr_array_index (identity_array, 5);
    g_assert (G_VALUE_HOLDS_BOXED (value));

    info->methods = g_hash_table_new_full (g_str_hash, g_str_equal,
                                            g_free, (GDestroyNotify)g_strfreev);
    g_hash_table_foreach ((GHashTable *)g_value_get_boxed(value),
                                            identity_value_to_stringarray,
                                                info->methods);
    g_value_unset (value);
    /* get the accessControlList (gchar**) */
    value = g_ptr_array_index (identity_array, 6);
    g_assert (G_VALUE_TYPE (value) == G_TYPE_STRV);
    signon_identity_info_set_realms (info, (const gchar* const *)g_value_get_boxed (value));
    g_value_unset (value);

    /* get the type (gint) */
    value = g_ptr_array_index (identity_array, 7);
    g_assert (G_VALUE_HOLDS_INT(value));
    signon_identity_info_set_identity_type (info, g_value_get_int (value));
    g_value_unset (value);

    return info;
}

static void
identity_process_updated (SignonIdentity *self)
{
    DEBUG ("%d %s", __LINE__, __func__);

    g_return_if_fail (self != NULL);
    g_return_if_fail (self->priv != NULL);

    SignonIdentityPrivate *priv = self->priv;
    g_return_if_fail (priv->state != NOT_READY);
    g_return_if_fail (priv->proxy != NULL);

    signon_identity_info_free (priv->identity_info);
    priv->identity_info = NULL;
    priv->updated = FALSE;
}

static void
identity_process_removed (SignonIdentity *self)
{
    g_return_if_fail (self != NULL);
    g_return_if_fail (self->priv != NULL);

    DEBUG ("%d %s", __LINE__, __func__);

    SignonIdentityPrivate *priv = self->priv;

    if (priv->state == REMOVED)
        return;

    priv->state = REMOVED;
    signon_identity_info_free (priv->identity_info);
    priv->identity_info = NULL;

    g_object_set (self, "id", 0, NULL);
    priv->id = 0;
}

static void
identity_process_signout(SignonIdentity *self)
{
    g_return_if_fail (self != NULL);
    g_return_if_fail (self->priv != NULL);

    DEBUG ("%d %s", __LINE__, __func__);
    SignonIdentityPrivate *priv = self->priv;

    if (priv->signed_out == TRUE)
        return;

    GSList *llink = priv->sessions;
    while (llink)
    {
        GSList *next = llink->next;
        g_object_unref (G_OBJECT(llink->data));
        llink = next;
    }

    priv->signed_out = TRUE;
    g_signal_emit(G_OBJECT(self), signals[SIGNEDOUT_SIGNAL], 0);
}

/*
 * TODO: fix the implementation
 * of signond: it returns result = TRUE
 * in ANY CASE
 * */
static void
identity_signout_reply (DBusGProxy *proxy,
                        gboolean result,
                        GError *error,
                        gpointer userdata)
{
    GError *new_error = NULL;
    IdentityVoidCbData *cb_data = (IdentityVoidCbData *)userdata;

    g_return_if_fail (cb_data != NULL);
    g_return_if_fail (cb_data->self != NULL);
    g_return_if_fail (cb_data->self->priv != NULL);

    new_error = _signon_errors_get_error_from_dbus (error);

    if (cb_data->cb)
    {
        (cb_data->cb) (cb_data->self, new_error, cb_data->user_data);
    }

    g_clear_error(&new_error);
    g_slice_free (IdentityVoidCbData, cb_data);
}

static void
identity_removed_reply (DBusGProxy *proxy,
                        GError *error,
                        gpointer userdata)
{
    GError *new_error = NULL;
    IdentityVoidCbData *cb_data = (IdentityVoidCbData *)userdata;

    g_return_if_fail (cb_data != NULL);
    g_return_if_fail (cb_data->self != NULL);
    g_return_if_fail (cb_data->self->priv != NULL);

    new_error = _signon_errors_get_error_from_dbus (error);

    if (cb_data->cb)
    {
        (cb_data->cb) (cb_data->self, new_error, cb_data->user_data);
    }

    g_clear_error(&new_error);
    g_slice_free (IdentityVoidCbData, cb_data);
}

static void
identity_info_reply(DBusGProxy *proxy, GPtrArray *identity_array,
                    GError *error, gpointer userdata)
{
    DEBUG ("%d %s", __LINE__, __func__);

    GError *new_error = NULL;
    IdentityInfoCbData *cb_data = (IdentityInfoCbData *)userdata;

    g_return_if_fail (cb_data != NULL);
    g_return_if_fail (cb_data->self != NULL);
    g_return_if_fail (cb_data->self->priv != NULL);

    SignonIdentityPrivate *priv = cb_data->self->priv;

    new_error = _signon_errors_get_error_from_dbus (error);
    priv->identity_info = identity_ptrarray_to_identity_info (identity_array);
    g_ptr_array_free (identity_array, TRUE);

    if (cb_data->cb)
    {
        (cb_data->cb) (cb_data->self, priv->identity_info, new_error, cb_data->user_data);
    }

    g_clear_error(&new_error);
    g_slice_free (IdentityInfoCbData, cb_data);

    priv->updated = TRUE;
}

static void
identity_info_ready_cb(gpointer object, const GError *error, gpointer user_data)
{
    g_return_if_fail (SIGNON_IS_IDENTITY (object));

    SignonIdentity *self = SIGNON_IDENTITY (object);
    SignonIdentityPrivate *priv = self->priv;
    g_return_if_fail (priv != NULL);

    DEBUG ("%s %d", G_STRFUNC, __LINE__);

    IdentityVoidData *operation_data =
        (IdentityVoidData *)user_data;
    g_return_if_fail (operation_data != NULL);

    IdentityInfoCbData *cb_data = operation_data->cb_data;
    g_return_if_fail (cb_data != NULL);

    if (priv->state == REMOVED)
    {
        GError *new_error = g_error_new (signon_error_quark(),
                                         SIGNON_ERROR_NOT_FOUND,
                                         "Already removed from database.");
        if (cb_data->cb)
        {
            (cb_data->cb) (self, NULL, new_error, cb_data->user_data);
        }

        g_error_free (new_error);
    }
    else if (error || priv->id == 0)
    {
        if (error)
            DEBUG ("IdentityError: %s", error->message);
        else
            DEBUG ("Identity is not stored and has no info yet");

        if (cb_data->cb)
        {
            (cb_data->cb) (self, NULL, error, cb_data->user_data);
        }
    }
    else if (priv->updated == FALSE)
    {
        g_return_if_fail (priv->proxy != NULL);
        com_nokia_singlesignon_SignonIdentity_query_info_async (
                                                        priv->proxy,
                                                        identity_info_reply,
                                                        cb_data);
    }
    else
    {
        if (cb_data->cb)
        {
            (cb_data->cb) (self, priv->identity_info, error, cb_data->user_data);
        }
    }

    if (priv->updated == TRUE)
        g_slice_free (IdentityInfoCbData, cb_data);

    g_slice_free (IdentityVoidData, operation_data);
}

static void
identity_signout_ready_cb(gpointer object, const GError *error, gpointer user_data)
{
    g_return_if_fail (SIGNON_IS_IDENTITY (object));

    SignonIdentity *self = SIGNON_IDENTITY (object);
    SignonIdentityPrivate *priv = self->priv;
    g_return_if_fail (priv != NULL);

    DEBUG ("%s %d", G_STRFUNC, __LINE__);
    IdentityVoidCbData *cb_data = (IdentityVoidCbData *)user_data;

    g_return_if_fail (cb_data != NULL);

    if (priv->state == REMOVED)
    {
        GError *new_error = g_error_new (signon_error_quark(),
                                         SIGNON_ERROR_NOT_FOUND,
                                         "Already removed from database.");
        if (cb_data->cb)
        {
            (cb_data->cb) (self, new_error, cb_data->user_data);
        }

        g_error_free (new_error);
        g_slice_free (IdentityVoidCbData, cb_data);
    }
    else if (error)
    {
        DEBUG ("IdentityError: %s", error->message);
        if (cb_data->cb)
        {
            (cb_data->cb) (self, error, cb_data->user_data);
        }

        g_slice_free (IdentityVoidCbData, cb_data);
    }
    else
    {
        g_return_if_fail (priv->proxy != NULL);
        com_nokia_singlesignon_SignonIdentity_sign_out_async(
                priv->proxy,
                identity_signout_reply,
                cb_data);
    }
}

static void
identity_remove_ready_cb(gpointer object, const GError *error, gpointer user_data)
{
    g_return_if_fail (SIGNON_IS_IDENTITY (object));

    SignonIdentity *self = SIGNON_IDENTITY (object);
    SignonIdentityPrivate *priv = self->priv;
    g_return_if_fail (priv != NULL);

    DEBUG ("%s %d", G_STRFUNC, __LINE__);
    IdentityVoidCbData *cb_data = (IdentityVoidCbData *)user_data;
    g_return_if_fail (cb_data != NULL);

    if (priv->state == REMOVED)
    {
        GError *new_error = g_error_new (signon_error_quark(),
                                         SIGNON_ERROR_NOT_FOUND,
                                         "Already removed from database.");
        if (cb_data->cb)
        {
            (cb_data->cb) (self, new_error, cb_data->user_data);
        }

        g_error_free (new_error);
        g_slice_free (IdentityVoidCbData, cb_data);
    }
    else if (error)
    {
        DEBUG ("IdentityError: %s", error->message);
        if (cb_data->cb)
        {
            (cb_data->cb) (self, error, cb_data->user_data);
        }

        g_slice_free (IdentityVoidCbData, cb_data);
    }
    else
    {
        g_return_if_fail (priv->proxy != NULL);
        com_nokia_singlesignon_SignonIdentity_remove_async(
                priv->proxy,
                identity_removed_reply,
                cb_data);
    }
}

void static
identity_void_operation(SignonIdentity *self,
                        gint operation,
                        gpointer cb_data)
{
    g_return_if_fail (SIGNON_IS_IDENTITY (self));

    SignonIdentityPrivate *priv = self->priv;
    g_return_if_fail (priv != NULL);

    DEBUG ("%s %d", G_STRFUNC, __LINE__);

    IdentityVoidData *operation_data = g_slice_new0 (IdentityVoidData);
    operation_data->cb_data = cb_data;
    _signon_object_call_when_ready (self,
                                    identity_object_quark(),
                                    identity_info_ready_cb,
                                    operation_data);
}

/**
 * signon_identity_remove:
 * @cb: callback
 * @user_data : user_data.
 *
 * Removes correspondent credentials record
 */
void signon_identity_remove(SignonIdentity *self,
                           SignonIdentityRemovedCb cb,
                           gpointer user_data)
{
    g_return_if_fail (SIGNON_IS_IDENTITY (self));

    SignonIdentityPrivate *priv = self->priv;
    g_return_if_fail (priv != NULL);

    IdentityVoidCbData *cb_data = g_slice_new0 (IdentityVoidCbData);
    cb_data->self = self;
    cb_data->cb = (SignonIdentityVoidCb)cb;
    cb_data->user_data = user_data;

    DEBUG ("%s %d", G_STRFUNC, __LINE__);

    _signon_object_call_when_ready (self,
                                    identity_object_quark(),
                                    identity_remove_ready_cb,
                                    cb_data);
}

/**
 * signon_identity_signout:
 * @cb: callback
 * @user_data : user_data.
 *
 * Makes SignOut
 */
void signon_identity_signout(SignonIdentity *self,
                             SignonIdentitySignedOutCb cb,
                             gpointer user_data)
{
    g_return_if_fail (SIGNON_IS_IDENTITY (self));

    SignonIdentityPrivate *priv = self->priv;
    g_return_if_fail (priv != NULL);

    IdentityVoidCbData *cb_data = g_slice_new0 (IdentityVoidCbData);
    cb_data->self = self;
    cb_data->cb = (SignonIdentityVoidCb)cb;
    cb_data->user_data = user_data;

    _signon_object_call_when_ready (self,
                                    identity_object_quark(),
                                    identity_signout_ready_cb,
                                    cb_data);
}

/**
 * signon_identity_info:
 * @cb: callback
 * @user_data : user_data.
 *
 * Returns info of the associated record in credentials DB (NULL for new identity)
 */
void signon_identity_query_info(SignonIdentity *self,
                                SignonIdentityInfoCb cb,
                                gpointer user_data)
{
    g_return_if_fail (SIGNON_IS_IDENTITY (self));

    SignonIdentityPrivate *priv = self->priv;
    g_return_if_fail (priv != NULL);

    IdentityInfoCbData *cb_data = g_slice_new0 (IdentityInfoCbData);
    cb_data->self = self;
    cb_data->cb = cb;
    cb_data->user_data = user_data;

    identity_void_operation(self,
                            SIGNON_INFO,
                            cb_data);
}

SignonIdentityInfo *signon_identity_info_new ()
{
    SignonIdentityInfo *info = g_slice_new0 (SignonIdentityInfo);
    info->methods = g_hash_table_new_full (g_str_hash, g_str_equal,
                                            g_free, (GDestroyNotify)g_strfreev);
    info->store_secret = FALSE;

    return info;
}

void signon_identity_info_free (SignonIdentityInfo *info)
{
    if (info == NULL) return;

    g_free (info->username);
    g_free (info->secret);
    g_free (info->caption);

    g_hash_table_destroy (info->methods);

    g_strfreev (info->realms);
    g_strfreev (info->access_control_list);

    g_slice_free (SignonIdentityInfo, info);
}

SignonIdentityInfo *signon_identity_info_copy (const SignonIdentityInfo *other)
{
    g_return_val_if_fail (other != NULL, NULL);
    SignonIdentityInfo *info = signon_identity_info_new ();

    identity_info_set_id (info, signon_identity_info_get_id (other));

    signon_identity_info_set_username (info, signon_identity_info_get_username (other));

    signon_identity_info_set_secret (info, identity_info_get_secret(other),
                                      signon_identity_info_get_storing_secret (other));

    signon_identity_info_set_caption (info, signon_identity_info_get_caption(other));

    identity_info_set_methods (info, signon_identity_info_get_methods (other));

    signon_identity_info_set_realms (info, signon_identity_info_get_realms (other));

    signon_identity_info_set_access_control_list (info,
                            signon_identity_info_get_access_control_list (other));

    signon_identity_info_set_identity_type (info, signon_identity_info_get_identity_type (other));

    return info;
}

gint signon_identity_info_get_id (const SignonIdentityInfo *info)
{
    g_return_val_if_fail (info != NULL, -1);
    return info->id;
}

const gchar *signon_identity_info_get_username (const SignonIdentityInfo *info)
{
    g_return_val_if_fail (info != NULL, NULL);
    return info->username;
}

gboolean signon_identity_info_get_storing_secret (const SignonIdentityInfo *info)
{
    g_return_val_if_fail (info != NULL, FALSE);
    return info->store_secret;
}

const gchar *signon_identity_info_get_caption (const SignonIdentityInfo *info)
{
    g_return_val_if_fail (info != NULL, NULL);
    return info->caption;
}

const GHashTable *signon_identity_info_get_methods (const SignonIdentityInfo *info)
{
    g_return_val_if_fail (info != NULL, NULL);
    return info->methods;
}

const gchar* const *signon_identity_info_get_realms (const SignonIdentityInfo *info)
{
    g_return_val_if_fail (info != NULL, NULL);
    return (const gchar* const *)info->realms;
}

const gchar* const *signon_identity_info_get_access_control_list (const SignonIdentityInfo *info)
{
    g_return_val_if_fail (info != NULL, NULL);
    return (const gchar* const *)info->access_control_list;
}

SignonIdentityType signon_identity_info_get_identity_type (const SignonIdentityInfo *info)
{
    g_return_val_if_fail (info != NULL, -1);
    return (SignonIdentityType)info->type;
}

void signon_identity_info_set_username (SignonIdentityInfo *info, const gchar *username)
{
    g_return_if_fail (info != NULL);

    if (info->username) g_free (info->username);

    info->username = g_strdup (username);
}

void signon_identity_info_set_secret (SignonIdentityInfo *info, const gchar *secret,
                                            gboolean store_secret)
{
    g_return_if_fail (info != NULL);

    if (info->secret) g_free (info->secret);

    info->secret = g_strdup (info->secret);
    info->store_secret = store_secret;
}

void signon_identity_info_set_caption (SignonIdentityInfo *info, const gchar *caption)
{
    g_return_if_fail (info != NULL);

    if (info->caption) g_free (info->caption);

    info->caption = g_strdup (caption);
}

void signon_identity_info_set_method (SignonIdentityInfo *info, const gchar *method, const gchar* const *mechanisms)
{
    g_return_if_fail (info != NULL);

    g_return_if_fail (info->methods != NULL);
    g_return_if_fail (method != NULL);
    g_return_if_fail (mechanisms != NULL);

    g_hash_table_replace (info->methods, g_strdup(method), g_strdupv((gchar **)mechanisms));
}

void signon_identity_info_remove_method (SignonIdentityInfo *info, const gchar *method)
{
    g_return_if_fail (info != NULL);
    g_return_if_fail (info->methods != NULL);

    g_hash_table_remove (info->methods, method);
}

void signon_identity_info_set_realms (SignonIdentityInfo *info, const gchar* const *realms)
{
    g_return_if_fail (info != NULL);

    if (info->realms) g_strfreev (info->realms);

    info->realms = g_strdupv ((gchar **)realms);
}

void signon_identity_info_set_access_control_list (SignonIdentityInfo *info,
                                                    const gchar* const *access_control_list)
{
    g_return_if_fail (info != NULL);

    if (info->access_control_list) g_strfreev (info->access_control_list);

    info->access_control_list = g_strdupv ((gchar **)access_control_list);
}

void signon_identity_info_set_identity_type (SignonIdentityInfo *info, SignonIdentityType type)
{
    g_return_if_fail (info != NULL);
    info->type = (gint)type;
}

static const gchar *identity_info_get_secret (const SignonIdentityInfo *info)
{
    g_return_val_if_fail (info != NULL, NULL);

    return info->secret;
}

static void identity_info_set_id (SignonIdentityInfo *info, gint id)
{
    g_return_if_fail (info != NULL);
    g_return_if_fail (id >= 0);

    info->id = id;
}

static void identity_methods_copy (gpointer key, gpointer value, gpointer user_data)
{
    signon_identity_info_set_method ((SignonIdentityInfo *)user_data,
                                     (const gchar *)key,
                                     (const gchar* const *)value);
}

static void identity_info_set_methods (SignonIdentityInfo *info, const GHashTable *methods)
{
    g_return_if_fail (info != NULL);
    g_return_if_fail (methods != NULL);

    DEBUG("%s", G_STRFUNC);

    if (info->methods)
        g_hash_table_remove_all (info->methods);
    else
        info->methods = g_hash_table_new_full (g_str_hash, g_str_equal,
                                                g_free, (GDestroyNotify)g_strfreev);

    g_hash_table_foreach ((GHashTable *)methods, identity_methods_copy, info);
}
