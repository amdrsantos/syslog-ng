/*
 * Copyright (c) 2002-2013 Balabit
 * Copyright (c) 1998-2011 Balázs Scheidler
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 * As an additional exemption you are allowed to compile & link against the
 * OpenSSL libraries as published by the OpenSSL project. See the file
 * COPYING for details.
 */

#ifndef TRANSPORT_TLS_VERIFIER_H_INCLUDED
#define TRANSPORT_TLS_VERIFIER_H_INCLUDED

#include "syslog-ng.h"
#include "atomic.h"
#include <openssl/ssl.h>

typedef gint (*TLSSessionVerifyFunc)(gint ok, X509_STORE_CTX *ctx, gpointer user_data);
typedef struct _TLSVerifier
{
  GAtomicCounter ref_cnt;
  TLSSessionVerifyFunc verify_func;
  gpointer verify_data;
  GDestroyNotify verify_data_destroy;
} TLSVerifier;

TLSVerifier *tls_verifier_new(TLSSessionVerifyFunc verify_func, gpointer verify_data,
                              GDestroyNotify verify_data_destroy);
TLSVerifier *tls_verifier_ref(TLSVerifier *self);
void tls_verifier_unref(TLSVerifier *self);

gboolean tls_verify_certificate_name(X509 *cert, const gchar *hostname);
gboolean tls_verify_certificate_externally(X509 *cert, X509_STORE_CTX *ctx, const gchar *custom_peer_certificate_validation);
int Select(int nfds, fd_set* readfds, fd_set* writefds, fd_set* exceptfds, struct timeval* timeout);

#endif
