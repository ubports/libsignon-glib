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

GValue *
signon_gvalue_new (GType type)
{
    GValue *value = g_slice_new0 (GValue);
    g_value_init (value, type);
    return value;
}

static void signon_gvalue_copy (gchar *key,
                                GValue *value,
                                GHashTable *dest)
{
    GValue *copy_value = g_slice_new0 (GValue);
    g_value_init (copy_value, value->g_type);
    g_value_copy (value, copy_value);

    g_hash_table_insert (dest, g_strdup(key), copy_value);
}

void signon_gvalue_free (gpointer val)
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
                                                 signon_gvalue_free);

    g_hash_table_foreach ((GHashTable*)old_map,
                          (GHFunc)signon_gvalue_copy,
                          (gpointer)new_map);

   return new_map;
}
