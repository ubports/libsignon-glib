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
#include "signon-internals.h"
#include "signon-proxy.h"
#include "signon-identity-glib-gen.h"
#include "signon-client-glib-gen.h"
#include <glib.h>

#define SIGNON_IDENTITY_IFACE  "com.nokia.singlesignon.SignonIdentity"

G_DEFINE_TYPE (SignonIdentity, signon_identity, G_TYPE_OBJECT);

enum
{
    PROP_0,

    PROP_ID
};

typedef struct _SignonIdentityInfo
{
    gchar *user_name;
    gchar *password;
    gchar *caption;
} SignonIdentityInfo;

struct _SignonIdentityPrivate
{
    SignonProxy *signon_proxy;
    SignonIdentityInfo *identityInfo;
    GError *last_error;
    guint id;
};

void _signon_identity_info_free (SignonIdentityInfo *identity_info)
{
    g_return_if_fail (identity_info != NULL);

    g_free (identity_info->user_name);
    g_free (identity_info->password);
    g_free (identity_info->caption);
    g_slice_free (SignonIdentityInfo, identity_info);
}

#define SIGNON_IDENTITY_PRIV(obj) (SIGNON_IDENTITY(obj)->priv)

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
    identity->priv = G_TYPE_INSTANCE_GET_PRIVATE (identity, SIGNON_TYPE_IDENTITY,
                                                  SignonIdentityPrivate);
    identity->priv->signon_proxy = signon_proxy_new();
}

static void
signon_identity_dispose (GObject *object)
{
    SignonIdentity *identity = SIGNON_IDENTITY (object);
    SignonIdentityPrivate *priv = identity->priv;

    if (priv->identityInfo)
    {
        _signon_identity_info_free (priv->identityInfo);
        priv->identityInfo = NULL;
    }

    if (priv->last_error)
        g_error_free (priv->last_error);

    if (priv->signon_proxy)
    {
        g_object_unref (priv->signon_proxy);
        priv->signon_proxy = NULL;
    }

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
                               0, G_MAXUINT, 0,
                               G_PARAM_CONSTRUCT_ONLY | G_PARAM_READWRITE);

    g_object_class_install_property (object_class,
                                     PROP_ID,
                                     pspec);

    g_type_class_add_private (object_class, sizeof (SignonIdentityPrivate));

    object_class->dispose = signon_identity_dispose;
    object_class->finalize = signon_identity_finalize;
}

void
_signon_identity_registered (SignonIdentity *identity, DBusGProxy *proxy,
                             char *objectPath, GPtrArray *identityArray,
                             GError *error)
{
    g_return_if_fail (SIGNON_IS_IDENTITY (identity));
    g_return_if_fail (objectPath != NULL);

    SignonIdentityPrivate *priv;
    priv = identity->priv;

    if (error)
    {
        g_warning ("%s: %s", G_STRFUNC, error->message);

        if (priv->last_error)
            g_error_free (priv->last_error);

        priv->last_error = error;

        return;
    }

    priv->identityInfo = g_slice_new(SignonIdentityInfo);

    GValue *value;

    /* get the user name (gchar*) */
    value = g_ptr_array_index (identityArray, 1);
    g_assert (G_VALUE_HOLDS_STRING(value));
    priv->identityInfo->user_name = g_value_dup_string (value);
    g_value_unset (value);

    /* get the password (gchar*) */
    value = g_ptr_array_index (identityArray, 2);
    g_assert (G_VALUE_HOLDS_STRING(value));
    priv->identityInfo->password = g_value_dup_string (value);
    g_value_unset (value);

    /* get the caption (gchar*) */
    value = g_ptr_array_index (identityArray, 3);
    g_assert (G_VALUE_HOLDS_STRING(value));
    priv->identityInfo->caption = g_value_dup_string (value);
    g_value_unset (value);

    g_ptr_array_free (identityArray, TRUE);
}

gchar*
signon_identity_get_username (SignonIdentity *identity)
{
    g_return_val_if_fail (SIGNON_IS_IDENTITY (identity), NULL);
    SignonIdentityPrivate *priv;

    priv = SIGNON_IDENTITY_PRIV (identity);

    return priv->identityInfo->user_name;
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
identity_new_from_db_cb (DBusGProxy *proxy, char *objectPath,
                         GPtrArray *identityData,
                         GError *error, gpointer userdata)
{
    SignonIdentity *identity = (SignonIdentity*)userdata;
    GError *new_error = NULL;
    g_return_if_fail (identity != NULL);

    if (error)
        new_error = _signon_errors_get_error_from_dbus (error);

    _signon_identity_registered (identity, proxy, objectPath, identityData, new_error);
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

    if (id == 0)
        return NULL;

    identity = g_object_new (SIGNON_TYPE_IDENTITY, "id", id, NULL);
    g_return_val_if_fail (SIGNON_IS_IDENTITY (identity), NULL);

    com_nokia_singlesignon_SignonDaemon_register_stored_identity_async
        (DBUS_G_PROXY (identity->priv->signon_proxy), id, identity_new_from_db_cb, identity);

    return identity;
}
