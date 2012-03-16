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

#include "signon-errors.h"
#include "signon-enum-types.h"
#include "signon-internals.h"
#include <dbus/dbus-glib.h>

/**
 * SECTION:signon-errors
 * @title: SignonError
 * @short_description: Possible errors from Signon.
 *
 * An enumeration of errors that are possible from Signon.
 */
#define SIGNON_ERROR_PREFIX SIGNOND_SERVICE_PREFIX ".Error"

GQuark signon_error_quark (void)
{
    static gsize quark = 0;

    if (g_once_init_enter (&quark))
    {
        GQuark domain = g_quark_from_static_string ("signon-errors");

        g_assert (sizeof (GQuark) <= sizeof (gsize));

        g_type_init ();
        dbus_g_error_domain_register (domain, SIGNON_ERROR_PREFIX, SIGNON_TYPE_ERROR);
        g_once_init_leave (&quark, domain);
    }
    return (GQuark) quark;
}

GError *
_signon_errors_get_error_from_dbus (GError *error)
{
    const gchar *error_name;
    const gchar *nick;
    GType enum_type;
    GEnumClass *enum_class;
    GEnumValue *enum_value;
    GError *new_error;
    gint code = SIGNON_ERROR_UNKNOWN;

    if (error == NULL)
        return NULL;

    error_name = dbus_g_error_get_name (error);

    if (!g_str_has_prefix (error_name, SIGNON_ERROR_PREFIX))
        return error;

    nick = error_name + sizeof(SIGNON_ERROR_PREFIX);

    enum_type = signon_error_get_type ();
    enum_class = g_type_class_ref (enum_type);
    enum_value = g_enum_get_value_by_nick (enum_class, nick);

    if (enum_value)
        code = enum_value->value;

    new_error = g_error_new_literal (SIGNON_ERROR, code, error->message);

    g_error_free (error);
    g_type_class_unref (enum_class);

    return new_error;
}
