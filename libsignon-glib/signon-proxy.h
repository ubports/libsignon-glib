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

#ifndef _SIGNON_AUTH_PROXY_H_
#define _SIGNON_AUTH_PROXY_H_


#include <glib-object.h>
#include <dbus/dbus-glib.h>

#define SIGNON_TYPE_PROXY             (signon_proxy_get_type ())
#define SIGNON_PROXY(obj)             (G_TYPE_CHECK_INSTANCE_CAST ((obj), SIGNON_TYPE_PROXY, SignonProxy))
#define SIGNON_PROXY_CLASS(klass)     (G_TYPE_CHECK_CLASS_CAST ((klass), SIGNON_TYPE_PROXY, SignonProxyClass))
#define SIGNON_IS_PROXY(obj)          (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SIGNON_TYPE_PROXY))
#define SIGNON_IS_PROXY_CLASS(klass)  (G_TYPE_CHECK_CLASS_TYPE ((klass), SIGNON_TYPE_PROXY))
#define SIGNON_PROXY_GET_CLASS(obj)   (G_TYPE_INSTANCE_GET_CLASS ((obj), SIGNON_TYPE_PROXY, SignonProxyClass))


typedef struct _SignonProxyClass SignonProxyClass;
typedef struct _SignonProxy SignonProxy;

struct _SignonProxyClass
{
    DBusGProxyClass parent_class;
};

struct _SignonProxy
{
    DBusGProxyClass parent_instance;
};

G_GNUC_INTERNAL
GType signon_proxy_get_type (void) G_GNUC_CONST;

G_GNUC_INTERNAL
SignonProxy *signon_proxy_new ();

G_END_DECLS

#endif /* _SIGNON_PROXY_H_ */
