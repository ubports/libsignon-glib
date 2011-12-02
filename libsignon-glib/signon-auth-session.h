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

#ifndef SIGNONAUTHSESSION_H_
#define SIGNONAUTHSESSION_H_

#include <glib-object.h>

G_BEGIN_DECLS

/*
 * Useful session data keys
 */
#define SIGNON_SESSION_DATA_USERNAME      "UserName"
#define SIGNON_SESSION_DATA_SECRET        "Secret"
#define SIGNON_SESSION_DATA_REALM         "Realm"
#define SIGNON_SESSION_DATA_PROXY         "NetworkProxy"
typedef enum {
    SignonPolicyDefault = 0,       /**< Plugin can decide when to show ui. */
    SignonPolicyRequestPassword,   /**< Force user to enter password. */
    SignonPolicyNoUserInteraction, /**< No ui elements are shown to user. */
    /**
     * UI elements can be shown to the user only when captcha-like security
     * measures are required.
    */
    SignonPolicyValidation,
} SignonSessionDataUiPolicy;
#define SIGNON_SESSION_DATA_UI_POLICY     "UiPolicy"
/* Caption for the UI dialog. */
#define SIGNON_SESSION_DATA_CAPTION       "Caption"
/* Network timeout, in milliseconds (uint32). */
#define SIGNON_SESSION_DATA_TIMEOUT       "NetworkTimeout"
/* Platform-specific window id (for dialog transiency) - uint32. */
#define SIGNON_SESSION_DATA_WINDOW_ID     "WindowId"
/* Requests the signon plugin to obtain a new token (boolean) */
#define SIGNON_SESSION_DATA_RENEW_TOKEN   "RenewToken"


#define SIGNON_TYPE_AUTH_SESSION                 (signon_auth_session_get_type ())
#define SIGNON_AUTH_SESSION(obj)                 (G_TYPE_CHECK_INSTANCE_CAST ((obj), SIGNON_TYPE_AUTH_SESSION, SignonAuthSession))
#define SIGNON_AUTH_SESSION_CLASS(klass)         (G_TYPE_CHECK_CLASS_CAST ((klass), SIGNON_TYPE_AUTH_SESSION, SignonAuthSessionClass))
#define SIGNON_IS_AUTH_SESSION(obj)              (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SIGNON_TYPE_AUTH_SESSION))
#define SIGNON_IS_AUTH_SESSION_CLASS(klass)      (G_TYPE_CHECK_CLASS_TYPE ((klass), SIGNON_TYPE_AUTH_SESSION))
#define SIGNON_AUTH_SESSION_GET_CLASS(obj)       (G_TYPE_INSTANCE_GET_CLASS ((obj), SIGNON_TYPE_AUTH_SESSION, SignonAuthSessionClass))

typedef struct _SignonAuthSession        SignonAuthSession;
typedef struct _SignonAuthSessionPrivate SignonAuthSessionPrivate;
typedef struct _SignonAuthSessionClass   SignonAuthSessionClass;

struct _SignonAuthSession {
    GObject parent;

    SignonAuthSessionPrivate *priv;
};

struct _SignonAuthSessionClass {
    GObjectClass parent;
};

GType signon_auth_session_get_type (void) G_GNUC_CONST;

SignonAuthSession *signon_auth_session_new(gint id,
                                           const gchar *method_name,
                                           GError **err);

const gchar *signon_auth_session_get_method (SignonAuthSession *self);

typedef void (*SignonAuthSessionQueryAvailableMechanismsCb) (
                    SignonAuthSession* self,
                    gchar **mechanisms,
                    const GError *error,
                    gpointer user_data);

G_GNUC_DEPRECATED
typedef SignonAuthSessionQueryAvailableMechanismsCb
    SignonAuthSessionQueryAvailableMethodsCb;

void signon_auth_session_query_available_mechanisms(SignonAuthSession *self,
                                                    const gchar **wanted_mechanisms,
                                                    SignonAuthSessionQueryAvailableMechanismsCb cb,
                                                    gpointer user_data);

typedef void (*SignonAuthSessionProcessCb) (SignonAuthSession *self,
                                            GHashTable *session_data,
                                            const GError *error,
                                            gpointer user_data);
void signon_auth_session_process(SignonAuthSession *self,
                                const GHashTable *session_data,
                                const gchar *mechanism,
                                SignonAuthSessionProcessCb cb,
                                gpointer user_data);

void signon_auth_session_cancel(SignonAuthSession *self);

G_END_DECLS

#endif //SIGNONAUTHSESSIONIMPL_H_
