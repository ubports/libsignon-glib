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

#include "signon-proxy.h"
#include "signon-internals.h"
#include <dbus/dbus-glib.h>

G_DEFINE_TYPE (SignonProxy, signon_proxy, DBUS_TYPE_G_PROXY);

static SignonProxy *signon_proxy = NULL;

static void
signon_proxy_init (SignonProxy *self)
{
}

static GObject *
signon_proxy_constructor (GType type, guint n_params,
                          GObjectConstructParam *params)
{
    GObjectClass *object_class =
        (GObjectClass *)signon_proxy_parent_class;
    GObject *object;

    if (!signon_proxy)
    {
        object = object_class->constructor (type,
                                            n_params,
                                            params);
        signon_proxy = SIGNON_PROXY (object);
    }
    else
        object = g_object_ref (G_OBJECT (signon_proxy));

    return object;
}

static void
signon_proxy_dispose (GObject *object)
{
    G_OBJECT_CLASS (signon_proxy_parent_class)->dispose (object);
}

static void
signon_proxy_finalize (GObject *object)
{
    G_OBJECT_CLASS (signon_proxy_parent_class)->finalize (object);
}

static void
signon_proxy_class_init (SignonProxyClass *klass)
{
    GObjectClass *object_class = G_OBJECT_CLASS (klass);

    object_class->dispose = signon_proxy_dispose;
    object_class->constructor = signon_proxy_constructor;
    object_class->finalize = signon_proxy_finalize;
}

SignonProxy *
signon_proxy_new ()
{
    SignonProxy *proxy;
    GError *error = NULL;

    DBusGConnection *connection = dbus_g_bus_get (DBUS_BUS_SESSION, &error);

    if (error)
    {
        g_warning ("%s returned error: %s", G_STRFUNC, error->message);
        g_error_free (error);
        return NULL;
    }

    proxy = g_object_new (SIGNON_TYPE_PROXY,
                          "name", SIGNOND_SERVICE,
                          "path", SIGNOND_DAEMON_OBJECTPATH,
                          "interface", SIGNOND_DAEMON_INTERFACE,
                          "connection", connection,
                          NULL);

    dbus_g_connection_unref (connection);

    return proxy;
}
