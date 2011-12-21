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
#include "signon-utils.h"

#ifdef ENABLE_PYGOBJECT_HACK
static gboolean
signon_demarshal_joined_values (const gchar *key,
                                const GValue *value,
                                GHashTable *dest)
{
    /* Hack to support marshalling of string arrays in python. See also the
     * "GI overrides" file in the pygobject directory */
    GValue *copy_value;
    const gchar *full_string, *joined_values;
    gchar separator[2];
    gchar **values;
    full_string = g_value_get_string (value);
    if (full_string == NULL || !g_str_has_prefix (full_string, "pySignon"))
        return FALSE;

    separator[0] = full_string[8];
    separator[1] = '\0';
    joined_values = full_string + 9;
    values = g_strsplit (joined_values, separator, 0);

    copy_value = g_slice_new0 (GValue);
    g_value_init (copy_value, G_TYPE_STRV);
    g_value_take_boxed (copy_value, values);

    g_hash_table_insert (dest, g_strdup(key), copy_value);
    return TRUE;
}
#endif

static void signon_copy_gvalue (gchar *key,
                                GValue *value,
                                GHashTable *dest)
{
#ifdef ENABLE_PYGOBJECT_HACK
    if (G_VALUE_HOLDS_STRING(value) &&
        signon_demarshal_joined_values (key, value, dest)) return;
#endif

    GValue *copy_value = g_slice_new0 (GValue);
    g_value_init (copy_value, value->g_type);
    g_value_copy (value, copy_value);

    g_hash_table_insert (dest, g_strdup(key), copy_value);
}

void signon_free_gvalue (gpointer val)
{
    g_return_if_fail (G_IS_VALUE(val));

    GValue *value = (GValue*)val;
    g_value_unset (value);
    g_slice_free (GValue, value);
}

GHashTable *signon_copy_variant_map (const GHashTable *old_map)
{
    if (old_map == NULL)
        return NULL;

    GHashTable *new_map = g_hash_table_new_full (g_str_hash,
                                                 g_str_equal,
                                                 g_free,
                                                 signon_free_gvalue);

    g_hash_table_foreach ((GHashTable*)old_map,
                          (GHFunc)signon_copy_gvalue,
                          (gpointer)new_map);

   return new_map;
}

void signon_stringarray_to_value (gpointer key, gpointer value, gpointer user_data)
{
    GValue *gvalue = g_value_init(g_slice_new0 (GValue), G_TYPE_STRV);
    g_value_set_boxed (gvalue, (gchar **)value);
    g_hash_table_insert ((GHashTable *)user_data, g_strdup((gchar *)key), gvalue);
}
