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

#define SIGNON_ERROR_PREFIX "com.nokia.singlesignon.Error"

#define SIGNON_ERROR (signon_error_quark())

typedef enum {
    SIGNON_ERROR_INTERNAL_SERVER, /*< nick=InternalServer >*/
    SIGNON_ERROR_METHOD_NOT_KNOWN, /*< nick=MethodNotKnown >*/
    SIGNON_ERROR_INVALID_QUERY, /*< nick=InvalidQuery >*/
    SIGNON_ERROR_PERMISSION_DENIED, /*< nick=PermissionDenied >*/
    SIGNON_ERROR_UNKNOWN, /*< nick=Unknown >*/
    SIGNON_ERROR_NOT_FOUND, /*< nick=NotFound >*/
    SIGNON_ERROR_METHOD_NOT_AVAILABLE, /*< nick=MethodNotAvaliable >*/
    SIGNON_ERROR_STORE_FAILED, /*< nick=StoreFailed >*/
    SIGNON_ERROR_REMOVE_FAILED, /*< nick=RemoveFailed >*/
    SIGNON_ERROR_SIGNOUT_FAILED, /*< nick=SignOutFailed >*/
    SIGNON_ERROR_CANCELED, /*< nick=Canceled >*/
    SIGNON_ERROR_CREDENTIALS_NOT_AVAILABLE, /*< nick=CredentialsNotAvailable >*/
    SIGNON_ERROR_MECHANISM_NOT_AVAILABLE, /*< nick=MechanismNotAvailable >*/
    SIGNON_ERROR_WRONG_STATE, /*< nick=WrongState >*/
    SIGNON_ERROR_OPERATION_NOT_SUPPORTED, /*< nick=OperationNotSupported >*/
    SIGNON_ERROR_NO_CONNECTION, /*< nick=NoConnection >*/
    SIGNON_ERROR_SSL, /*< nick=SslError >*/
    SIGNON_ERROR_TIMEDOUT, /*< nick=TimedOut >*/
    SIGNON_ERROR_RUNTIME /*< nick=Runtime >*/
} SignonError;

#define SignonError SignonError

GQuark signon_error_quark (void);


#endif
