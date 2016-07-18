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

#ifndef _SIGNON_PROXY_H_
#define _SIGNON_PROXY_H_

#include <glib.h>
#include <glib-object.h>

G_BEGIN_DECLS

#define SIGNON_TYPE_PROXY             (signon_proxy_get_type ())
G_GNUC_INTERNAL
G_DECLARE_INTERFACE(SignonProxy, signon_proxy, SIGNON, PROXY, GObject)

typedef void (*SignonReadyCb) (gpointer object, const GError *error,
                               gpointer user_data);

struct _SignonProxyInterface
{
    GTypeInterface parent_iface;

    void (*setup) (SignonProxy *self);
};

G_GNUC_INTERNAL
void signon_proxy_setup (gpointer self);

G_GNUC_INTERNAL
void signon_proxy_call_when_ready (gpointer self, GQuark quark,
                                   SignonReadyCb callback, gpointer user_data);

G_GNUC_INTERNAL
void signon_proxy_set_ready (gpointer self, GQuark quark, GError *error);

G_GNUC_INTERNAL
void signon_proxy_set_not_ready (gpointer self);

G_GNUC_INTERNAL
const GError *signon_proxy_get_last_error (gpointer self);

G_END_DECLS
#endif /* _SIGNON_PROXY_H_ */
