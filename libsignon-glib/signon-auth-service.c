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
 * SECTION:signon-auth-service
 * @title: SignonAuthService
 * @short_description: The authorization service object
 *
 * The #SignonAuthService is the main object in this library.
 */

#include "signon-auth-service.h"
#include "signon-client-glib-gen.h"
#include "signon-internals.h"
#include "signon-errors.h"
#include "signon-proxy.h"
#include <glib.h>

G_DEFINE_TYPE (SignonAuthService, signon_auth_service, G_TYPE_OBJECT);

struct _SignonAuthServicePrivate
{
    SignonProxy *signon_proxy;
};

typedef struct _MethodCbData
{
    SignonAuthService *service;
    SignonQueryMethodsCb cb;
    gpointer userdata;
} MethodCbData;

typedef struct _MechanismCbData
{
    SignonAuthService *service;
    SignonQueryMechanismCb cb;
    gpointer userdata;
    gchar *method;
} MechanismCbData;

#define SIGNON_AUTH_SERVICE_PRIV(obj) (SIGNON_AUTH_SERVICE(obj)->priv)

static void
signon_auth_service_init (SignonAuthService *auth_service)
{
    SignonAuthServicePrivate *priv;

    priv = G_TYPE_INSTANCE_GET_PRIVATE (auth_service, SIGNON_TYPE_AUTH_SERVICE,
                                        SignonAuthServicePrivate);
    auth_service->priv = priv;

    priv->signon_proxy = signon_proxy_new ();
}

static GObject *
signon_auth_service_constructor (GType type, guint n_params,
                                 GObjectConstructParam *params)
{
    GObjectClass *object_class =
        (GObjectClass *)signon_auth_service_parent_class;
    GObject *object;

    object = object_class->constructor (type, n_params, params);
    g_return_val_if_fail (SIGNON_IS_AUTH_SERVICE (object), NULL);

    return object;
}

static void
signon_auth_service_dispose (GObject *object)
{
    SignonAuthService *auth_service = SIGNON_AUTH_SERVICE (object);
    SignonAuthServicePrivate *priv = auth_service->priv;

    if (priv->signon_proxy)
    {
        g_object_unref (priv->signon_proxy);
        priv->signon_proxy = NULL;
    }

    G_OBJECT_CLASS (signon_auth_service_parent_class)->dispose (object);
}

static void
signon_auth_service_finalize (GObject *object)
{
    G_OBJECT_CLASS (signon_auth_service_parent_class)->finalize (object);
}

static void
signon_auth_service_class_init (SignonAuthServiceClass *klass)
{
    GObjectClass *object_class = G_OBJECT_CLASS (klass);

    g_type_class_add_private (object_class, sizeof (SignonAuthServicePrivate));

    object_class->dispose = signon_auth_service_dispose;
    object_class->constructor = signon_auth_service_constructor;
    object_class->finalize = signon_auth_service_finalize;
}

/**
 * signon_auth_service_new:
 *
 * Create a new #SignonAuthService.
 *
 * Returns: an instance of an #SignonAuthService.
 */
SignonAuthService *
signon_auth_service_new ()
{
    return g_object_new (SIGNON_TYPE_AUTH_SERVICE, NULL);
}

static void
auth_query_methods_cb (DBusGProxy *proxy, char **value,
                       GError *error, gpointer user_data)
{
    MethodCbData *data = (MethodCbData*)user_data;
    GError *new_error = NULL;
    g_return_if_fail (data != NULL);

    if (error)
    {
        new_error = _signon_errors_get_error_from_dbus (error);
        value = NULL;
    }

    (data->cb)
        (data->service, value, new_error, data->userdata);

    if (new_error)
        g_error_free (new_error);
    g_slice_free (MethodCbData, data);
}

static void
auth_query_mechanisms_cb (DBusGProxy *proxy, char **value,
                          GError *error, gpointer user_data)
{
    MechanismCbData *data = (MechanismCbData*) user_data;
    GError *new_error = NULL;
    g_return_if_fail (data != NULL);

    if (error)
    {
        new_error = _signon_errors_get_error_from_dbus (error);
        value = NULL;
    }

    (data->cb)
        (data->service, data->method, value, new_error, data->userdata);

    if (new_error)
        g_error_free (new_error);
    g_free (data->method);
    g_slice_free (MechanismCbData, data);
}

/**
 * SignonQueryMethodsCb:
 * @auth_service: the #SignonAuthService.
 * @methods: (transfer full) (type GStrv): list of available methods.
 * @error: a #GError if an error occurred, %NULL otherwise.
 * @user_data: the user data that was passed when installing this callback.
 *
 * Callback to be passed to signon_auth_service_query_methods().
 */

/**
 * signon_auth_service_query_methods:
 * @auth_service: the #SignonAuthService.
 * @cb: (scope async): callback to be invoked.
 * @user_data: user data.
 *
 * Lists all the available methods.
 */
void
signon_auth_service_query_methods (SignonAuthService *auth_service,
                                   SignonQueryMethodsCb cb,
                                   gpointer user_data)
{
    g_return_if_fail (SIGNON_IS_AUTH_SERVICE (auth_service));
    g_return_if_fail (cb != NULL);

    SignonAuthServicePrivate *priv;
    priv = SIGNON_AUTH_SERVICE_PRIV (auth_service);

    MethodCbData *cb_data;
    cb_data = g_slice_new (MethodCbData);
    cb_data->service = auth_service;
    cb_data->cb = cb;
    cb_data->userdata = user_data;

    SSO_AuthService_query_methods_async (DBUS_G_PROXY(priv->signon_proxy),
                                         auth_query_methods_cb,
                                         cb_data);
}

/**
 * SignonQueryMechanismCb:
 * @auth_service: the #SignonAuthService.
 * @method: the authentication method being inspected.
 * @mechanisms: (transfer full) (type GStrv): list of available mechanisms.
 * @error: a #GError if an error occurred, %NULL otherwise.
 * @user_data: the user data that was passed when installing this callback.
 *
 * Callback to be passed to signon_auth_service_query_mechanisms().
 */

/**
 * signon_auth_service_query_mechanisms:
 * @auth_service: the #SignonAuthService.
 * @method: the name of the method whose mechanisms must be
 * retrieved.
 * @cb: (scope async): callback to be invoked.
 * @user_data: user data.
 *
 * Lists all the available mechanisms.
 */
void
signon_auth_service_query_mechanisms (SignonAuthService *auth_service,
                                      const gchar *method,
                                      SignonQueryMechanismCb cb,
                                      gpointer user_data)
{
    g_return_if_fail (SIGNON_IS_AUTH_SERVICE (auth_service));
    g_return_if_fail (cb != NULL);

    MechanismCbData *cb_data;
    cb_data = g_slice_new (MechanismCbData);
    cb_data->service = auth_service;
    cb_data->cb = cb;
    cb_data->userdata = user_data;
    cb_data->method = g_strdup (method);

    SignonAuthServicePrivate *priv;
    priv = SIGNON_AUTH_SERVICE_PRIV (auth_service);

    SSO_AuthService_query_mechanisms_async (DBUS_G_PROXY(priv->signon_proxy),
                                            method,
                                            auth_query_mechanisms_cb,
                                            cb_data);
}
