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

#include "signon-identity.h"
#include <glib-object.h>

G_BEGIN_DECLS

#define SIGNON_SESSION_DATA_USERNAME      "UserName"
#define SIGNON_SESSION_DATA_SECRET        "Secret"
#define SIGNON_SESSION_DATA_REALM         "Realm"

enum AuthSessionState {
    SessionNotStarted = 0,          /**< No message. */
    HostResolving,                  /**< Resolving remote server host name. */
    ServerConnecting,               /**< Connecting to remote server. */
    DataSending,                    /**< Sending data to remote server. */
    ReplyWaiting,                   /**< Waiting reply from remote server. */
    UserPending,                    /**< Waiting response from user. */
    UiRefreshing,                   /**< Refreshing ui request. */
    ProcessPending,                 /**< Waiting another process to start. */
    SessionStarted,                 /**< Authentication session is started. */
    ProcessCanceling,               /**< Canceling.current process: is this really needed??? */
    ProcessDone,                    /** < ???? Is this really needed > */
    CustomState,                    /**< Custom message. */
    MaxState,
};

typedef enum
{
    AS_STATE_NOT_STARTED = 0,           /**< No message. */
    AS_STATE_HOST_RESOLVING,            /**< Resolving remote server host name. */
    AS_STATE_SERVER_CONNECTING,         /**< Connecting to remote server. */
    AS_STATE_DATA_SENDING,              /**< Sending data to remote server. */
    AS_STATE_DATA_WAITING,              /**< Waiting reply from remote server. */
    AS_STATE_USER_PENDING,
    AS_STATE_UI_REFRESHING,
    AS_STATE_PROCESS_PENDING,
    AS_STATE_SESSION_STARTED,
    AS_STATE_PROCESS_CANCELLING,
    AS_STATE_PROCESS_DONE,
    AS_STATE_CUSTOM_STATE,
    AS_STATE_MAX_STATE,
} SessionObjectState;


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
    gboolean dispose_has_run;
};

struct _SignonAuthSessionClass {
    GObjectClass parent;
};

GType signon_auth_session_get_type (void) G_GNUC_CONST;

typedef void (*SignonAuthSessionStateCahngedCb) (SignonAuthSession* self,
                                                 gint state,
                                                 gchar *message,
                                                 gpointer user_data);

/*
 * Despite my arguments it was decided to keep this
 * function as public
 * */
SignonAuthSession *signon_auth_session_new(gint id,
                                           const gchar *method_name,
                                           SignonAuthSessionStateCahngedCb cb,
                                           gpointer user_data,
                                           GError **err);

gchar *signon_auth_session_name(SignonAuthSession* self);

typedef void (*SignonAuthSessionQueryAvailableMethodsCb) (SignonAuthSession* self,
                                                          gchar **mechanisms,
                                                          const GError *error,
                                                          gpointer user_data);
void signon_auth_session_query_available_mechanisms(SignonAuthSession* self,
                                                   const gchar **wanted_mechanisms,
                                                   SignonAuthSessionQueryAvailableMethodsCb cb,
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
