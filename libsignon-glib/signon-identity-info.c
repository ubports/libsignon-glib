/* vi: set et sw=4 ts=4 cino=t0,(0: */
/* -*- Mode: C; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*
 * This file is part of libsignon-glib
 *
 * Copyright (C) 2009-2010 Nokia Corporation.
 * Copyright (C) 2011 Canonical Ltd.
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

/**
 * SECTION:signon-identity
 * @title: SignonIdentity
 * @short_description: client side presentation of a credential.
 *
 * The #SignonIdentity represents an database entry for a single identity.
 */

#include "signon-identity-info.h"

#include "signon-internals.h"

G_DEFINE_BOXED_TYPE (SignonIdentityInfo, signon_identity_info,
                     (GBoxedCopyFunc)signon_identity_info_copy,
                     (GBoxedFreeFunc)signon_identity_info_free);


static const gchar *identity_info_get_secret (const SignonIdentityInfo *info)
{
    g_return_val_if_fail (info != NULL, NULL);

    return info->secret;
}

static void identity_info_set_id (SignonIdentityInfo *info, gint id)
{
    g_return_if_fail (info != NULL);
    g_return_if_fail (id >= 0);

    info->id = id;
}

static void identity_methods_copy (gpointer key, gpointer value, gpointer user_data)
{
    signon_identity_info_set_method ((SignonIdentityInfo *)user_data,
                                     (const gchar *)key,
                                     (const gchar* const *)value);
}

static void identity_info_set_methods (SignonIdentityInfo *info,
                                       const GHashTable *methods)
{
    g_return_if_fail (info != NULL);
    g_return_if_fail (methods != NULL);

    DEBUG("%s", G_STRFUNC);

    if (info->methods)
        g_hash_table_remove_all (info->methods);
    else
        info->methods = g_hash_table_new_full (g_str_hash, g_str_equal,
                                               g_free, (GDestroyNotify)g_strfreev);

    g_hash_table_foreach ((GHashTable *)methods, identity_methods_copy, info);
}

static void
identity_value_to_stringarray (gpointer key, gpointer value, gpointer user_data)
{
    gchar **stringarray = (gchar **)g_value_get_boxed ((const GValue *)value);
    g_hash_table_insert ((GHashTable *)user_data, g_strdup((gchar *)key),
                         g_strdupv (stringarray));
}

SignonIdentityInfo *
identity_ptrarray_to_identity_info (const GPtrArray *identity_array)
{
    if (!identity_array)
        return NULL;

    SignonIdentityInfo *info = signon_identity_info_new ();

    DEBUG("%s: ", G_STRFUNC);
    GValue *value;

    /* get the id (gint) */
    value = g_ptr_array_index (identity_array, 0);
    g_assert (G_VALUE_HOLDS_UINT (value));
    identity_info_set_id (info, g_value_get_uint (value));
    g_value_unset (value);

    /* get the user name (gchar*) */
    value = g_ptr_array_index (identity_array, 1);
    g_assert (G_VALUE_HOLDS_STRING (value));
    signon_identity_info_set_username (info, g_value_get_string (value));
    g_value_unset (value);

    /* get the password (gchar*)
     * TODO: fix it as soon
     * as reply from server will
     * be changed
     * */

    value = g_ptr_array_index (identity_array, 2);
    g_assert (G_VALUE_HOLDS_STRING (value));
    info->store_secret = (g_value_get_string (value) != NULL);
    g_value_unset (value);

    /* get the caption (gchar*) */
    value = g_ptr_array_index (identity_array, 3);
    g_assert (G_VALUE_HOLDS_STRING (value));
    signon_identity_info_set_caption (info, g_value_get_string (value));
    g_value_unset (value);

    /* get the realms (gchar**) */
    value = g_ptr_array_index (identity_array, 4);
    g_assert (G_VALUE_TYPE (value) == G_TYPE_STRV);
    signon_identity_info_set_realms (info,
                                     (const gchar* const *)g_value_get_boxed (value));
    g_value_unset (value);

    /* get the methods GPtrArray (QVariantMap in original) */
    value = g_ptr_array_index (identity_array, 5);
    g_assert (G_VALUE_HOLDS_BOXED (value));

    info->methods = g_hash_table_new_full (g_str_hash, g_str_equal,
                                           g_free, (GDestroyNotify)g_strfreev);
    g_hash_table_foreach ((GHashTable *)g_value_get_boxed(value),
                          identity_value_to_stringarray,
                          info->methods);
    g_value_unset (value);
    /* get the accessControlList (gchar**) */
    value = g_ptr_array_index (identity_array, 6);
    g_assert (G_VALUE_TYPE (value) == G_TYPE_STRV);
    signon_identity_info_set_access_control_list (info,
                                     (const gchar* const *)g_value_get_boxed (value));
    g_value_unset (value);

    /* get the type (gint) */
    value = g_ptr_array_index (identity_array, 7);
    g_assert (G_VALUE_HOLDS_INT(value));
    signon_identity_info_set_identity_type (info, g_value_get_int (value));
    g_value_unset (value);

    /* get the ref_count (gint) */
    value = g_ptr_array_index (identity_array, 8);
    g_assert (G_VALUE_HOLDS_INT(value));
    signon_identity_info_set_identity_ref_count (info, g_value_get_int (value));
    g_value_unset (value);

    return info;
}

/*
 * Public methods:
 */

SignonIdentityInfo *signon_identity_info_new ()
{
    SignonIdentityInfo *info = g_slice_new0 (SignonIdentityInfo);
    info->methods = g_hash_table_new_full (g_str_hash, g_str_equal,
                                            g_free, (GDestroyNotify)g_strfreev);
    info->store_secret = FALSE;

    return info;
}

void signon_identity_info_free (SignonIdentityInfo *info)
{
    if (info == NULL) return;

    g_free (info->username);
    g_free (info->secret);
    g_free (info->caption);

    g_hash_table_destroy (info->methods);

    g_strfreev (info->realms);
    g_strfreev (info->access_control_list);

    g_slice_free (SignonIdentityInfo, info);
}

SignonIdentityInfo *signon_identity_info_copy (const SignonIdentityInfo *other)
{
    g_return_val_if_fail (other != NULL, NULL);
    SignonIdentityInfo *info = signon_identity_info_new ();

    identity_info_set_id (info, signon_identity_info_get_id (other));

    signon_identity_info_set_username (info, signon_identity_info_get_username (other));

    signon_identity_info_set_secret (info, identity_info_get_secret(other),
                                     signon_identity_info_get_storing_secret (other));

    signon_identity_info_set_caption (info, signon_identity_info_get_caption(other));

    identity_info_set_methods (info, signon_identity_info_get_methods (other));

    signon_identity_info_set_realms (info, signon_identity_info_get_realms (other));

    signon_identity_info_set_access_control_list (info,
        signon_identity_info_get_access_control_list (other));

    signon_identity_info_set_identity_type (info,
        signon_identity_info_get_identity_type (other));

    signon_identity_info_set_identity_ref_count (info,
        signon_identity_info_get_identity_ref_count (other));

    return info;
}

gint signon_identity_info_get_id (const SignonIdentityInfo *info)
{
    g_return_val_if_fail (info != NULL, -1);
    return info->id;
}

const gchar *signon_identity_info_get_username (const SignonIdentityInfo *info)
{
    g_return_val_if_fail (info != NULL, NULL);
    return info->username;
}

gboolean signon_identity_info_get_storing_secret (const SignonIdentityInfo *info)
{
    g_return_val_if_fail (info != NULL, FALSE);
    return info->store_secret;
}

const gchar *signon_identity_info_get_caption (const SignonIdentityInfo *info)
{
    g_return_val_if_fail (info != NULL, NULL);
    return info->caption;
}

const GHashTable *signon_identity_info_get_methods (const SignonIdentityInfo *info)
{
    g_return_val_if_fail (info != NULL, NULL);
    return info->methods;
}

const gchar* const *signon_identity_info_get_realms (const SignonIdentityInfo *info)
{
    g_return_val_if_fail (info != NULL, NULL);
    return (const gchar* const *)info->realms;
}

const gchar* const *signon_identity_info_get_access_control_list (const SignonIdentityInfo *info)
{
    g_return_val_if_fail (info != NULL, NULL);
    return (const gchar* const *)info->access_control_list;
}

SignonIdentityType signon_identity_info_get_identity_type (const SignonIdentityInfo *info)
{
    g_return_val_if_fail (info != NULL, -1);
    return (SignonIdentityType)info->type;
}

gint signon_identity_info_get_identity_ref_count (const SignonIdentityInfo *info)
{
    g_return_val_if_fail (info != NULL, -1);
    return (SignonIdentityType)info->ref_count;
}

void signon_identity_info_set_username (SignonIdentityInfo *info, const gchar *username)
{
    g_return_if_fail (info != NULL);

    if (info->username) g_free (info->username);

    info->username = g_strdup (username);
}

void signon_identity_info_set_secret (SignonIdentityInfo *info, const gchar *secret,
                                      gboolean store_secret)
{
    g_return_if_fail (info != NULL);

    if (info->secret) g_free (info->secret);

    info->secret = g_strdup (info->secret);
    info->store_secret = store_secret;
}

void signon_identity_info_set_caption (SignonIdentityInfo *info, const gchar *caption)
{
    g_return_if_fail (info != NULL);

    if (info->caption) g_free (info->caption);

    info->caption = g_strdup (caption);
}

void signon_identity_info_set_method (SignonIdentityInfo *info, const gchar *method,
                                      const gchar* const *mechanisms)
{
    g_return_if_fail (info != NULL);

    g_return_if_fail (info->methods != NULL);
    g_return_if_fail (method != NULL);
    g_return_if_fail (mechanisms != NULL);

    g_hash_table_replace (info->methods,
                          g_strdup(method), g_strdupv((gchar **)mechanisms));
}

void signon_identity_info_remove_method (SignonIdentityInfo *info, const gchar *method)
{
    g_return_if_fail (info != NULL);
    g_return_if_fail (info->methods != NULL);

    g_hash_table_remove (info->methods, method);
}

void signon_identity_info_set_realms (SignonIdentityInfo *info,
                                      const gchar* const *realms)
{
    g_return_if_fail (info != NULL);

    if (info->realms) g_strfreev (info->realms);

    info->realms = g_strdupv ((gchar **)realms);
}

void signon_identity_info_set_access_control_list (SignonIdentityInfo *info,
                                                   const gchar* const *access_control_list)
{
    g_return_if_fail (info != NULL);

    if (info->access_control_list) g_strfreev (info->access_control_list);

    info->access_control_list = g_strdupv ((gchar **)access_control_list);
}

void signon_identity_info_set_identity_type (SignonIdentityInfo *info,
                                             SignonIdentityType type)
{
    g_return_if_fail (info != NULL);
    info->type = (gint)type;
}

void signon_identity_info_set_identity_ref_count (SignonIdentityInfo *info,
                                                  gint ref_count)
{
    g_return_if_fail (info != NULL);
    info->ref_count = ref_count;
}
