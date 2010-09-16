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

#ifndef _SIGNON_IDENTITY_H_
#define _SIGNON_IDENTITY_H_

#include "signon-auth-session.h"
#include <glib-object.h>
#include <dbus/dbus-glib.h>

G_BEGIN_DECLS

#define SIGNON_TYPE_IDENTITY             (signon_identity_get_type ())
#define SIGNON_IDENTITY(obj)             (G_TYPE_CHECK_INSTANCE_CAST ((obj), SIGNON_TYPE_IDENTITY, SignonIdentity))
#define SIGNON_IDENTITY_CLASS(klass)     (G_TYPE_CHECK_CLASS_CAST ((klass), SIGNON_TYPE_IDENTITY, SignonIdentityClass))
#define SIGNON_IS_IDENTITY(obj)          (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SIGNON_TYPE_IDENTITY))
#define SIGNON_IS_IDENTITY_CLASS(klass)  (G_TYPE_CHECK_CLASS_TYPE ((klass), SIGNON_TYPE_IDENTITY))
#define SIGNON_IDENTITY_GET_CLASS(obj)   (G_TYPE_INSTANCE_GET_CLASS ((obj), SIGNON_TYPE_IDENTITY, SignonIdentityClass))

typedef struct _SignonIdentityClass SignonIdentityClass;
typedef struct _SignonIdentityPrivate SignonIdentityPrivate;
typedef struct _SignonIdentity SignonIdentity;
typedef struct _SignonIdentityInfo SignonIdentityInfo;

struct _SignonIdentityClass
{
    GObjectClass parent_class;
};

struct _SignonIdentity
{
    GObject parent_instance;
    SignonIdentityPrivate *priv;
};

typedef void (*SignonIdentityVoidCb) (SignonIdentity *self,
                                      const GError *error,
                                      gpointer user_data);

typedef SignonIdentityVoidCb SignonIdentityRemovedCb;
typedef SignonIdentityVoidCb SignonIdentitySignedOutCb;

/*
 * types used in SignonIdentityInfo
 * */
enum _SignonIdentityType {
    SIGNON_TYPE_OTHER = 0,
    SIGNON_TYPE_APP = 1 << 0,
    SIGNON_TYPE_WEB = 1 << 1,
    SIGNON_TYPE_NETWORK = 1 << 2
};

typedef enum _SignonIdentityType SignonIdentityType;

GType signon_identity_get_type (void) G_GNUC_CONST;

SignonIdentity *signon_identity_new_from_db (guint32 id);
SignonIdentity *signon_identity_new ();

const GError *signon_identity_get_last_error (SignonIdentity *identity);

SignonAuthSession *signon_identity_create_session(SignonIdentity *self,
                                                  const gchar *method,
                                                  GError **error);

typedef void (*SignonIdentityStoreCredentialsCb) (SignonIdentity *self,
                                                  guint32 id,
                                                  const GError *error,
                                                  gpointer user_data);

/*
 * Later, as the structure SignonIdentityInfo will be brought
 * into use, we will announce signon_identity_store_credentials_with_args
 * or just simple signon_identity_store_credentials
 * */
void signon_identity_store_credentials_with_info(SignonIdentity *self,
                                                 const SignonIdentityInfo *info,
                                                 SignonIdentityStoreCredentialsCb cb,
                                                 gpointer user_data);

/*
 * Later, as the structure SignonIdentityInfo will be brought
 * into use, we will announce signon_identity_store_credentials_with_args
 * or just simple signon_identity_store_credentials
 * */
void signon_identity_store_credentials_with_args(SignonIdentity *self,
                                                 const gchar *username,
                                                 const gchar *secret,
                                                 const gboolean store_secret,
                                                 const GHashTable *methods,
                                                 const gchar *caption,
                                                 const gchar* const *realms,
                                                 const gchar* const *access_control_list,
                                                 SignonIdentityType type,
                                                 gint ref_count,
                                                 SignonIdentityStoreCredentialsCb cb,
                                                 gpointer user_data);

typedef void (*SignonIdentityVerifyCb) (SignonIdentity *self,
                                        gboolean valid,
                                        const GError *error,
                                        gpointer user_data);

void signon_identity_verify_user(SignonIdentity *self,
                                const gchar *message,
                                SignonIdentityVerifyCb cb,
                                gpointer user_data);

void signon_identity_verify_secret(SignonIdentity *self,
                                  const gchar *secret,
                                  SignonIdentityVerifyCb cb,
                                  gpointer user_data);

typedef void (*SignonIdentityInfoCb) (SignonIdentity *self,
                                      const SignonIdentityInfo *info,
                                      const GError *error,
                                      gpointer user_data);

void signon_identity_query_info(SignonIdentity *self,
                               SignonIdentityInfoCb cb,
                               gpointer user_data);

void signon_identity_remove(SignonIdentity *self,
                           SignonIdentityRemovedCb cb,
                           gpointer user_data);

void signon_identity_signout(SignonIdentity *self,
                            SignonIdentitySignedOutCb cb,
                            gpointer user_data);

SignonIdentityInfo *signon_identity_info_new ();

void signon_identity_info_free (SignonIdentityInfo *info);

SignonIdentityInfo *signon_identity_info_copy (const SignonIdentityInfo *other);

gint signon_identity_info_get_id (const SignonIdentityInfo *info);

const gchar *signon_identity_info_get_username (const SignonIdentityInfo *info);

gboolean signon_identity_info_get_storing_secret (const SignonIdentityInfo *info);

const gchar *signon_identity_info_get_caption (const SignonIdentityInfo *info);

const GHashTable *signon_identity_info_get_methods (const SignonIdentityInfo *info);

const gchar* const *signon_identity_info_get_realms (const SignonIdentityInfo *info);

const gchar* const *signon_identity_info_get_access_control_list (const SignonIdentityInfo *info);

SignonIdentityType signon_identity_info_get_identity_type (const SignonIdentityInfo *info);

gint signon_identity_info_get_identity_ref_count (const SignonIdentityInfo *info);

void signon_identity_info_set_username (SignonIdentityInfo *info, const gchar *username);

void signon_identity_info_set_secret (SignonIdentityInfo *info, const gchar *secret, gboolean store_secret);

void signon_identity_info_set_caption (SignonIdentityInfo *info, const gchar *caption);

void signon_identity_info_set_method (SignonIdentityInfo *info, const gchar *method, const gchar* const *mechanisms);

void signon_identity_info_remove_method (SignonIdentityInfo *info, const gchar *method);

void signon_identity_info_set_realms (SignonIdentityInfo *info, const gchar* const *realms);

void signon_identity_info_set_access_control_list (SignonIdentityInfo *info, const gchar* const *access_control_list);

void signon_identity_info_set_identity_type (SignonIdentityInfo *info, SignonIdentityType type);

void signon_identity_info_set_identity_ref_count (SignonIdentityInfo *info, gint ref_count);

G_END_DECLS

#endif /* _SIGNON_IDENTITY_H_ */
