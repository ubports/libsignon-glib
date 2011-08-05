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

#ifndef __LIBSIGNON_ERRORS_H__
#define __LIBSIGNON_ERRORS_H__

#include <glib.h>
#include <glib-object.h>
#include "signon-enum-types.h"

#define SIGNON_ERROR (signon_error_quark())

typedef enum {
    SIGNON_ERROR_UNKNOWN = 1,                  /**< Catch-all for errors not distinguished
                                                    by another code. */
    SIGNON_ERROR_INTERNAL_SERVER = 2,          /**< Signon Daemon internal error. */
    SIGNON_ERROR_INTERNAL_COMMUNICATION = 3,   /**< Communication with Signon Daemon error. */
    SIGNON_ERROR_PERMISSION_DENIED = 4,        /**< The operation cannot be performed due to
                                                    insufficient client permissions. */
    SIGNON_ERROR_ENCRYPTION_FAILURE,           /**< Failure during data encryption/decryption. */

    SIGNON_ERROR_AUTH_SERVICE = 100,           /* Placeholder to rearrange enumeration
                                     	 	    	- AuthService specific */
    SIGNON_ERROR_METHOD_NOT_KNOWN,            /**< The method with this name is not found. */
    SIGNON_ERROR_SERVICE_NOT_AVAILABLE,       /**< The service is temporarily unavailable. */
    SIGNON_ERROR_INVALID_QUERY,               /**< Parameters for the query are invalid. */

    SIGNON_ERROR_IDENTITY_ERROR = 200,        /* Placeholder to rearrange enumeration
                                     	 	 	 - Identity specific */

    SIGNON_ERROR_METHOD_NOT_AVAILABLE,        /**< The requested method is not available. */
    SIGNON_ERROR_IDENTITY_NOT_FOUND,          /**< The identity matching this Identity object
                                                was not found on the service. */
    SIGNON_ERROR_STORE_FAILED,                /**< Storing credentials failed. */
    SIGNON_ERROR_REMOVE_FAILED,               /**< Removing credentials failed. */
    SIGNON_ERROR_SIGNOUT_FAILED,              /**< SignOut failed. */
    SIGNON_ERROR_IDENTITY_OPERATION_CANCELED, /**< Identity operation was canceled by user. */
    SIGNON_ERROR_CREDENTIALS_NOT_AVAILABLE,   /**< Query fails. */
    SIGNON_ERROR_REFERENCE_NOT_FOUND,         /**< Trying to remove nonexistent reference. */

    SIGNON_ERROR_AUTH_SESSION_ERROR = 300,    /* Placeholder to rearrange enumeration
                                     	 	 	 - AuthSession/AuthPluginInterface specific */
    SIGNON_ERROR_MECHANISM_NOT_AVAILABLE,     /**< The requested mechanism is not available. */
    SIGNON_ERROR_MISSING_DATA,                /**< The SessionData object does not contain
                                                      necessary information. */
    SIGNON_ERROR_INVALID_CREDENTIALS,         /**< The supplied credentials are invalid for
                                                      the mechanism implementation. */
    SIGNON_ERROR_NOT_AUTHORIZED,             /**< Authorization failed. */
    SIGNON_ERROR_WRONG_STATE,                 /**< An operation method has been called in
                                                      a wrong state. */
    SIGNON_ERROR_OPERATION_NOT_SUPPORTED,     /**< The operation is not supported by the
                                                      mechanism implementation. */
    SIGNON_ERROR_NO_CONNECTION,              /**< No Network connetion. */
    SIGNON_ERROR_NETWORK,                    /**< Network connetion failed. */
    SIGNON_ERROR_SSL,                        /**< Ssl connetion failed. */
    SIGNON_ERROR_RUNTIME,                    /**< Casting SessionData into subclass failed */
    SIGNON_ERROR_SESSION_CANCELED,           /**< Challenge was canceled. */
    SIGNON_ERROR_TIMED_OUT,                  /**< Challenge was timed out. */
    SIGNON_ERROR_USER_INTERACTION,           /**< User interaction dialog failed */
    SIGNON_ERROR_OPERATION_FAILED,           /**< Temporary failure in authentication. */
    SIGNON_ERROR_ENCRYPTION_FAILED,          /**< @deprecated Failure during data encryption/decryption. */
    SIGNON_ERROR_TOS_NOT_ACCEPTED,           /**< User declined Terms of Service. */
    SIGNON_ERROR_FORGOT_PASSWORD,            /**< User requested reset password sequence. */
    SIGNON_ERROR_METHOD_OR_MECHANISM_NOT_ALLOWED, /**< Method or mechanism not allowed for this identity. */
    SIGNON_ERROR_INCORRECT_DATE,             /**< Date time incorrect on device. */
    SIGNON_ERROR_USER_ERROR = 400            /* Placeholder to rearrange enumeration
                                                      - User space specific */
} SignonError;

GQuark signon_error_quark (void);


#endif
