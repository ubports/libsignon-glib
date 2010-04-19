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

#define SIGNON_IDENTITY_IFACE  "com.nokia.singlesignon.SignonIdentity"

G_DEFINE_TYPE (SignonIdentity, signon_identity, G_TYPE_OBJECT);

enum
{
    PROP_0,

    PROP_ID
};

struct _SignonIdentityPrivate
{
    DBusGProxy *proxy;
    SignonProxy *signon_proxy;

    SignonIdentityInfo *identity_info;
    GError *last_error;

    GPtrArray *tmp_identity_ptrarray;
    GSList *sessions;

    guint id;
};

#define SIGNON_IDENTITY_PRIV(obj) (SIGNON_IDENTITY(obj)->priv)

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

enum {
    SIGNON_VERIFY_USER,
    SIGNON_VERIFY_SECRET
};

typedef struct _IdentityVerifyCbData
{
    SignonIdentity *self;
    SignonIdentityVerifyCb cb;
    gpointer user_data;
} IdentityVerifyCbData;

typedef struct _IdentityVerifyData
{
    gchar *data_to_send;
    gboolean verify_secret;
    gpointer cb_data;
} IdentityVerifyData;

typedef struct _IdentityStoreCredentialsCbData
{
    SignonIdentity *self;
    SignonIdentityStoreCredentialsCb cb;
    gpointer user_data;
} IdentityStoreCredentialsCbData;

static void identity_info_free (SignonIdentityInfo *identity_info);
static void identity_registered (SignonIdentity *identity, DBusGProxy *proxy, char *object_path,
                                 GPtrArray *identity_array, GError *error);
static void identity_new_cb (DBusGProxy *proxy, char *objectPath, GError *error, gpointer userdata);
static void identity_new_from_db_cb (DBusGProxy *proxy, char *objectPath, GPtrArray *identityData,
                                      GError *error, gpointer userdata);
static void identity_store_credentials_ready_cb (gpointer object, const GError *error, gpointer user_data);
static void identity_store_credentials_reply (DBusGProxy *proxy, guint id, GError *error, gpointer userdata);
static void identity_session_object_destroyed_cb (gpointer data, GObject *where_the_session_was);
static void identity_verify_data (SignonIdentity *self, const gchar *data_to_send, gboolean verify_secret,
                                    SignonIdentityVerifyCb cb, gpointer user_data);
static void identity_verify_ready_cb (gpointer object, const GError *error, gpointer user_data);
static void identity_verify_reply (DBusGProxy *proxy, gboolean valid, GError *error, gpointer userdata);


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

    identity->priv->proxy = NULL;
    identity->priv->tmp_identity_ptrarray = NULL;
    identity->priv->identity_info = NULL;
}

static void
signon_identity_dispose (GObject *object)
{
    SignonIdentity *identity = SIGNON_IDENTITY (object);
    SignonIdentityPrivate *priv = identity->priv;

    if (priv->identity_info)
    {
        identity_info_free (priv->identity_info);
        priv->identity_info = NULL;
    }

    if (priv->last_error)
        g_error_free (priv->last_error);

    if (priv->signon_proxy)
    {
        g_object_unref (priv->signon_proxy);
        priv->signon_proxy = NULL;
    }

    if (priv->tmp_identity_ptrarray)
    {
        g_ptr_array_free (priv->tmp_identity_ptrarray, TRUE);
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

    object_class->dispose = signon_identity_dispose;
    object_class->finalize = signon_identity_finalize;
}

static void
identity_info_free (SignonIdentityInfo *identity_info)
{
    g_return_if_fail (identity_info != NULL);

    g_free (identity_info->user_name);
    g_free (identity_info->password);
    g_free (identity_info->caption);

    g_slice_free (SignonIdentityInfo, identity_info);
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
        priv->proxy = dbus_g_proxy_new_from_proxy (DBUS_G_PROXY (priv->signon_proxy),
                                                   SIGNON_IDENTITY_IFACE,
                                                   object_path);
        DEBUG("%s: ", G_STRFUNC);

        if (identity_array)
        {
            priv->identity_info = g_slice_new(SignonIdentityInfo);

            DEBUG("%s: ", G_STRFUNC);
            GValue *value;

            /* get the user name (gchar*) */
            value = g_ptr_array_index (identity_array, 1);
            g_assert (G_VALUE_HOLDS_STRING(value));
            priv->identity_info->user_name = g_value_dup_string (value);
            g_value_unset (value);

            /* get the password (gchar*) */
            value = g_ptr_array_index (identity_array, 2);
            g_assert (G_VALUE_HOLDS_STRING(value));
            priv->identity_info->password = g_value_dup_string (value);
            g_value_unset (value);

            /* get the caption (gchar*) */
            value = g_ptr_array_index (identity_array, 3);
            g_assert (G_VALUE_HOLDS_STRING(value));
            priv->identity_info->caption = g_value_dup_string (value);
            g_value_unset (value);

            DEBUG("%s: %s %s %s", G_STRFUNC, priv->identity_info->user_name,
                                             priv->identity_info->password,
                                             priv->identity_info->caption);

            g_ptr_array_free (identity_array, TRUE);
        }
    }
    _signon_object_ready (identity, identity_object_quark (), error);
}

gchar*
signon_identity_get_username (SignonIdentity *identity)
{
    g_return_val_if_fail (SIGNON_IS_IDENTITY (identity), NULL);
    SignonIdentityPrivate *priv;

    DEBUG ("%s %d", G_STRFUNC, __LINE__);
    priv = identity->priv;
    g_return_val_if_fail(priv != NULL, NULL);
    g_return_val_if_fail(priv->identity_info != NULL, NULL);

    return g_strdup (priv->identity_info->user_name);
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
    identity->priv->id = id;

    com_nokia_singlesignon_SignonDaemon_register_stored_identity_async
        (DBUS_G_PROXY (identity->priv->signon_proxy), id, identity_new_from_db_cb, identity);

    g_return_val_if_fail (SIGNON_IS_IDENTITY (identity), NULL);

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
 * signon_identity_create_session:
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
        priv->sessions = g_slist_append(priv->sessions, session);
        g_object_weak_ref (G_OBJECT(session),
                           identity_session_object_destroyed_cb,
                           self);
        /*
         * if you want to delete the identity
         * you MUST to delete all authsessions
         * first
         * */
        g_object_ref (self);
    }

    return session;
}

/**
 * signon_identity_store_credentials:
 * @id: identity ID.
 * @info: info.
 * @store_secret: store secret flag.
 * @methods: methods.
 * @realms: relams.
 * @access_control_list: access control list.
 * @cb: callback
 * @user_data : user_data.
 *
 * Construct an identity object associated with an existing identity record.
 * Returns: an instance of an #SignonIdentity.
 */
void signon_identity_store_credentials_with_info(SignonIdentity *self,
                                                 const SignonIdentityInfo *info,
                                                 const gboolean store_secret,
                                                 const GHashTable *methods,
                                                 const gchar **realms,
                                                 const gchar **access_control_list,
                                                 const gint type,
                                                 SignonIdentityStoreCredentialsCb cb,
                                                 gpointer user_data)
{
    g_return_if_fail(info != NULL);
    signon_identity_store_credentials_with_args(self,
                                                info->user_name,
                                                info->password,
                                                store_secret,
                                                methods,
                                                info->caption,
                                                realms,
                                                access_control_list,
                                                type,
                                                cb,
                                                user_data);
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
                                                 const gchar **realms,
                                                 const gchar **access_control_list,
                                                 const gint type,
                                                 SignonIdentityStoreCredentialsCb cb,
                                                 gpointer user_data)
{
    g_return_if_fail (SIGNON_IS_IDENTITY (self));

    SignonIdentityPrivate *priv = self->priv;
    g_return_if_fail (priv != NULL);

    g_return_if_fail (type == SIGNON_TYPE_OTHER ||
                      type == SIGNON_TYPE_APP ||
                      type == SIGNON_TYPE_WEB ||
                      type == SIGNON_TYPE_NETWORK);

    DEBUG ("%s %d", G_STRFUNC, __LINE__);

    IdentityStoreCredentialsCbData *cb_data = g_slice_new0 (IdentityStoreCredentialsCbData);
    cb_data->self = self;
    cb_data->cb = cb;
    cb_data->user_data = user_data;

    IdentityStoreCredentialsData *operation_data = g_slice_new0 (IdentityStoreCredentialsData);

    operation_data->username = g_strdup (username);
    operation_data->secret = g_strdup (secret);
    operation_data->store_secret = store_secret;
    operation_data->methods = signon_copy_variant_map (methods);
    operation_data->caption = g_strdup (caption);
    operation_data->realms = g_strdupv((gchar **)realms);
    operation_data->access_control_list = g_strdupv((gchar **)access_control_list);
    operation_data->type = type;
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

        (cb_data->cb)
            (self, 0, error, cb_data->user_data);

        g_slice_free (IdentityStoreCredentialsCbData, cb_data);
    }
    else if (priv->proxy)
    {
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

        DEBUG ("%s %d", G_STRFUNC, __LINE__);

        GPtrArray *ptrarray = g_ptr_array_new_with_free_func(g_free);

        g_ptr_array_add(ptrarray, operation_data->username);
        g_ptr_array_add(ptrarray, operation_data->secret);
        g_ptr_array_add(ptrarray, operation_data->caption);

        priv->tmp_identity_ptrarray = ptrarray;
    }
    else if (!priv->proxy)
    {
        g_critical ("IdentityError: proxy is not initialized but error is NULL");
    }

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

    (cb_data->cb)
        (cb_data->self, id, new_error, cb_data->user_data);

    GPtrArray *ptrarray = priv->tmp_identity_ptrarray;

    if (error == NULL)
    {
        if (priv->identity_info)
        {
            g_free (priv->identity_info->user_name);
            g_free (priv->identity_info->password);
            g_free (priv->identity_info->caption);
        }
        else
            priv->identity_info = g_slice_new(SignonIdentityInfo);

        DEBUG ("%s %d", G_STRFUNC, __LINE__);

        priv->identity_info->user_name = g_strdup((gchar *)g_ptr_array_index (ptrarray, 0));
        priv->identity_info->password = g_strdup((gchar *)g_ptr_array_index (ptrarray, 1));
        priv->identity_info->caption = g_strdup((gchar *)g_ptr_array_index (ptrarray, 2));

        g_ptr_array_free (ptrarray, TRUE);
        priv->tmp_identity_ptrarray = NULL;

        GSList *slist = priv->sessions;

        while (slist)
        {
            SignonAuthSession *session = SIGNON_AUTH_SESSION (priv->sessions->data);
            signon_auth_session_set_id(session, id);
            slist = g_slist_next(slist);
        }

        g_object_set (cb_data->self, "id", id, NULL);
        cb_data->self->priv->id = id;
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

    (cb_data->cb)
        (cb_data->self, valid, new_error, cb_data->user_data);

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

    if (error)
    {
        DEBUG ("IdentityError: %s", error->message);

        (cb_data->cb)
            (self, FALSE, error, cb_data->user_data);

        g_slice_free (IdentityVerifyCbData, cb_data);
    }
    else if (priv->proxy)
    {
        DEBUG ("%s %d", G_STRFUNC, __LINE__);

        if (operation_data->verify_secret == SIGNON_VERIFY_SECRET)
            com_nokia_singlesignon_SignonIdentity_verify_secret_async(
                    priv->proxy,
                    operation_data->data_to_send,
                    identity_verify_reply,
                    cb_data);
        else if (operation_data->verify_secret == SIGNON_VERIFY_USER)
            com_nokia_singlesignon_SignonIdentity_verify_user_async(
                    priv->proxy,
                    operation_data->data_to_send,
                    identity_verify_reply,
                    cb_data);
    }
    else if (!priv->proxy)
    {
        g_critical ("IdentityError: proxy is not initialized but error is NULL");
    }

    g_free (operation_data->data_to_send);
    g_slice_free (IdentityVerifyData, operation_data);
}

static void
identity_verify_data(SignonIdentity *self,
                     const gchar *data_to_send,
                     gboolean verify_secret,
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
    operation_data->verify_secret = verify_secret;
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
void sigon_identity_verify_user(SignonIdentity *self,
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
void sigon_identity_verify_secret(SignonIdentity *self,
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
