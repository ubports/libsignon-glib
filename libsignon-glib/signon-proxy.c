/* vi: set et sw=4 ts=4 cino=t0,(0: */
/* -*- Mode: C; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*
 * This file is part of libsignon-glib
 *
 * Copyright (C) 2009-2010 Nokia Corporation.
 * Copyright (C) 2012-2016 Canonical Ltd.
 *
 * Contact: Alberto Mardegan <alberto.mardegan@canonical.com>
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

G_DEFINE_INTERFACE (SignonProxy, signon_proxy, G_TYPE_OBJECT)

typedef struct {
    SignonReadyCb callback;
    gpointer user_data;
} SignonReadyCbData;

typedef struct {
    gpointer self;
    GSList *callbacks;
    guint idle_id;
} SignonReadyData;

static void
signon_proxy_default_init (SignonProxyInterface *iface)
{
    /* add properties and signals to the interface here */
}

static GQuark
_signon_proxy_ready_quark()
{
  static GQuark quark = 0;

  if (!quark)
    quark = g_quark_from_static_string ("signon_proxy_ready_quark");

  return quark;
}

static GQuark
_signon_proxy_error_quark()
{
  static GQuark quark = 0;

  if (!quark)
    quark = g_quark_from_static_string ("signon_proxy_error_quark");

  return quark;
}

static void
signon_proxy_invoke_ready_callbacks (SignonReadyData *rd, const GError *error)
{
    GSList *list;
    /* Make a copy of the callbacks list and erase the pointer in the
     * structure, to ensure that we won't invoke the same callback twice. */
    GSList *callbacks = rd->callbacks;
    rd->callbacks = NULL;

    for (list = callbacks; list != NULL; list = list->next)
    {
        SignonReadyCbData *cb = list->data;

        cb->callback (rd->self, error, cb->user_data);
        g_slice_free (SignonReadyCbData, cb);
    }
    g_slist_free (callbacks);
}

static void
signon_ready_data_free (SignonReadyData *rd)
{
    if (rd->self)
    {
        //TODO: Signon error codes need be presented instead of 555 and 666
        GError error = { 555, 666, "Object disposed" };
        signon_proxy_invoke_ready_callbacks (rd, &error);
    }
    if (rd->idle_id > 0)
    {
        g_source_remove (rd->idle_id);
        rd->idle_id = 0;
    }
    g_slice_free (SignonReadyData, rd);
}

static gboolean
signon_proxy_call_when_ready_idle (SignonReadyData *rd)
{
    if (GPOINTER_TO_INT (g_object_get_qdata((GObject*)rd->self,
                           _signon_proxy_ready_quark())) == TRUE)
    {
        //TODO: specify the last error in object initialization
        GError * err = g_object_get_qdata((GObject*)rd->self,
                                          _signon_proxy_error_quark());
        signon_proxy_invoke_ready_callbacks (rd, err);
    }
    else
    {
        signon_proxy_setup (SIGNON_PROXY (rd->self));
    }

    rd->idle_id = 0;
    return FALSE;
}

void
signon_proxy_setup (gpointer self)
{
    SignonProxyInterface *iface;

    g_return_if_fail (SIGNON_IS_PROXY (self));

    iface = SIGNON_PROXY_GET_IFACE (self);
    if (iface->setup != NULL)
    {
        iface->setup (self);
    }
}

void
signon_proxy_call_when_ready (gpointer object, GQuark quark, SignonReadyCb callback,
                              gpointer user_data)
{
    SignonReadyData *rd;
    SignonReadyCbData *cb;

    g_return_if_fail (SIGNON_IS_PROXY (object));
    g_return_if_fail (quark != 0);
    g_return_if_fail (callback != NULL);

    cb = g_slice_new (SignonReadyCbData);
    cb->callback = callback;
    cb->user_data = user_data;

    rd = g_object_get_qdata ((GObject *)object, quark);
    if (!rd)
    {
        rd = g_slice_new (SignonReadyData);
        rd->self = object;
        rd->callbacks = NULL;
        rd->idle_id = 0;
        g_object_set_qdata_full ((GObject *)object, quark, rd,
                                 (GDestroyNotify)signon_ready_data_free);
    }

    rd->callbacks = g_slist_append (rd->callbacks, cb);
    if (rd->idle_id == 0)
    {
        rd->idle_id =
            g_idle_add ((GSourceFunc)signon_proxy_call_when_ready_idle, rd);
    }
}

void
signon_proxy_set_ready (gpointer object, GQuark quark, GError *error)
{
    SignonReadyData *rd;

    g_return_if_fail (SIGNON_IS_PROXY (object));

    g_object_set_qdata((GObject *)object, _signon_proxy_ready_quark(), GINT_TO_POINTER(TRUE));

    if(error)
        g_object_set_qdata_full ((GObject *)object, _signon_proxy_error_quark(),
                                 error,
                                 (GDestroyNotify)g_error_free);

    rd = g_object_get_qdata ((GObject *)object, quark);
    if (!rd) return;

    g_object_ref (object);

    signon_proxy_invoke_ready_callbacks (rd, error);

    g_object_unref (object);
}

void
signon_proxy_set_not_ready (gpointer object)
{
    g_return_if_fail (SIGNON_IS_PROXY (object));

    g_object_set_qdata ((GObject *)object,
                        _signon_proxy_ready_quark(),
                        GINT_TO_POINTER(FALSE));

    g_object_set_qdata ((GObject *)object,
                        _signon_proxy_error_quark(),
                        NULL);
}

const GError *
signon_proxy_get_last_error (gpointer object)
{
    g_return_val_if_fail (SIGNON_IS_PROXY (object), NULL);

    return g_object_get_qdata((GObject *)object,
                              _signon_proxy_error_quark());
}
