/* vi: set et sw=4 ts=4 cino=t0,(0: */
/* -*- Mode: C; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*
 * This file is part of libsignon-glib
 *
 * Copyright (C) 2012 Canonical Ltd.
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

#ifndef SIGNON_TYPES_H
#define SIGNON_TYPES_H

#include <glib.h>

G_BEGIN_DECLS

#ifdef SIGNON_DISABLE_DEPRECATION_WARNINGS
#define SIGNON_DEPRECATED
#define SIGNON_DEPRECATED_FOR(x)
#else
#define SIGNON_DEPRECATED           G_DEPRECATED
#define SIGNON_DEPRECATED_FOR(x)    G_DEPRECATED_FOR(x)
#endif

G_END_DECLS

#endif /* SIGNON_TYPES_H */
