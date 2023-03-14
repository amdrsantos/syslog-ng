/*
 * Copyright (c) 2002-2011 Balabit
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
#include "tls-verifier.h"
#include "messages.h"
#include "compat/openssl_support.h"
#include <openssl/x509v3.h>
#include <sys/un.h>
#include <unistd.h>
#include <sys/select.h>


/* TLSVerifier */

TLSVerifier *
tls_verifier_new(TLSSessionVerifyFunc verify_func, gpointer verify_data,
                 GDestroyNotify verify_data_destroy)
{
  TLSVerifier *self = g_new0(TLSVerifier, 1);

  g_atomic_counter_set(&self->ref_cnt, 1);
  self->verify_func = verify_func;
  self->verify_data = verify_data;
  self->verify_data_destroy = verify_data_destroy;
  return self;
}

TLSVerifier *
tls_verifier_ref(TLSVerifier *self)
{
  g_assert(!self || g_atomic_counter_get(&self->ref_cnt) > 0);

  if (self)
    g_atomic_counter_inc(&self->ref_cnt);

  return self;
}

static void
_tls_verifier_free(TLSVerifier *self)
{
  g_assert(self);

  if (self)
    {
      if (self->verify_data && self->verify_data_destroy)
        self->verify_data_destroy(self->verify_data);
      g_free(self);
    }
}

void
tls_verifier_unref(TLSVerifier *self)
{
  g_assert(!self || g_atomic_counter_get(&self->ref_cnt));

  if (self && (g_atomic_counter_dec_and_test(&self->ref_cnt)))
    _tls_verifier_free(self);
}

/* helper functions */

static gboolean
tls_wildcard_match(const gchar *host_name, const gchar *pattern)
{
  gchar **pattern_parts, **hostname_parts;
  gboolean success = FALSE;
  gchar *lower_pattern = NULL;
  gchar *lower_hostname = NULL;
  gint i;

  pattern_parts = g_strsplit(pattern, ".", 0);
  hostname_parts = g_strsplit(host_name, ".", 0);
  for (i = 0; pattern_parts[i]; i++)
    {
      if (!hostname_parts[i])
        {
          /* number of dot separated entries is not the same in the hostname and the pattern spec */
          goto exit;
        }

      lower_pattern = g_ascii_strdown(pattern_parts[i], -1);
      lower_hostname = g_ascii_strdown(hostname_parts[i], -1);

      if (!g_pattern_match_simple(lower_pattern, lower_hostname))
        goto exit;
    }
  success = TRUE;
exit:
  g_free(lower_pattern);
  g_free(lower_hostname);
  g_strfreev(pattern_parts);
  g_strfreev(hostname_parts);
  return success;
}

gboolean
tls_verify_certificate_name(X509 *cert, const gchar *host_name)
{
  gchar pattern_buf[256];
  gint ext_ndx;
  gboolean found = FALSE, result = FALSE;

  ext_ndx = X509_get_ext_by_NID(cert, NID_subject_alt_name, -1);
  if (ext_ndx >= 0)
    {
      /* ok, there's a subjectAltName extension, check that */
      X509_EXTENSION *ext;
      STACK_OF(GENERAL_NAME) *alt_names;
      GENERAL_NAME *gen_name;

      ext = X509_get_ext(cert, ext_ndx);
      alt_names = X509V3_EXT_d2i(ext);
      if (alt_names)
        {
          gint num, i;

          num = sk_GENERAL_NAME_num(alt_names);

          for (i = 0; !result && i < num; i++)
            {
              gen_name = sk_GENERAL_NAME_value(alt_names, i);
              if (gen_name->type == GEN_DNS)
                {
                  const guchar *dnsname = ASN1_STRING_get0_data(gen_name->d.dNSName);
                  guint dnsname_len = ASN1_STRING_length(gen_name->d.dNSName);

                  if (dnsname_len > sizeof(pattern_buf) - 1)
                    {
                      found = TRUE;
                      result = FALSE;
                      break;
                    }

                  memcpy(pattern_buf, dnsname, dnsname_len);
                  pattern_buf[dnsname_len] = 0;
                  /* we have found a DNS name as alternative subject name */
                  found = TRUE;
                  result = tls_wildcard_match(host_name, pattern_buf);
                }
              else if (gen_name->type == GEN_IPADD)
                {
                  gchar dotted_ip[64] = {0};
                  int addr_family = AF_INET;
                  if (gen_name->d.iPAddress->length == 16)
                    addr_family = AF_INET6;

                  if (inet_ntop(addr_family, gen_name->d.iPAddress->data, dotted_ip, sizeof(dotted_ip)))
                    {
                      g_strlcpy(pattern_buf, dotted_ip, sizeof(pattern_buf));
                      found = TRUE;
                      result = strcasecmp(host_name, pattern_buf) == 0;
                    }
                }
            }
          sk_GENERAL_NAME_free(alt_names);
        }
    }
  if (!found)
    {
      /* hmm. there was no subjectAltName (this is deprecated, but still
       * widely used), look up the Subject, most specific CN */
      X509_NAME *name;

      name = X509_get_subject_name(cert);
      if (X509_NAME_get_text_by_NID(name, NID_commonName, pattern_buf, sizeof(pattern_buf)) != -1)
        {
          result = tls_wildcard_match(host_name, pattern_buf);
        }
    }
  if (!result)
    {
      msg_error("Certificate subject does not match configured hostname",
                evt_tag_str("hostname", host_name),
                evt_tag_str("certificate", pattern_buf));
    }
  else
    {
      msg_verbose("Certificate subject matches configured hostname",
                  evt_tag_str("hostname", host_name),
                  evt_tag_str("certificate", pattern_buf));
    }

  return result;
}

/* select wrapper to deal with select returning EINTR on signal delivery */
int Select(int nfds, fd_set* readfds, fd_set* writefds, fd_set* exceptfds, struct timeval* timeout)
{
  int ret;

  do
  {
    ret = select(nfds, readfds, writefds, exceptfds, timeout);
  }
  while((ret < 0) && (errno == EINTR));

  return ret;
}

gboolean tls_verify_certificate_externally(X509 *cert, X509_STORE_CTX *ctx, const gchar *custom_peer_certificate_validation)
{
  msg_notice("Triggering external peer certificate validation");

  BIO* bio = NULL;
  char* pData = NULL;
  long bytesAvailable = 0;
  int fd = 0;
  int errorCode = 0;

  char depth[1] = {0};
  depth[0] = (char)X509_STORE_CTX_get_error_depth(ctx);

  // Access the raw certificate bytes via a BIO.
  bio = BIO_new(BIO_s_mem());

  if(!bio)
  {
      msg_notice("Could not allocate BIO for peer certificate");
      return 0;
  }

  if(PEM_write_bio_X509(bio, cert) <= 0)
  {
      msg_notice("Could not extract peer certificate bytes");
      goto out_error;
  }

  bytesAvailable = BIO_get_mem_data(bio, &pData);

  if(bytesAvailable <= 0)
  {
      msg_notice("Could not access peer certificate bytes");
      goto out_error;
  }

  // Call External Validator API for certificate validation.
  {
      ssize_t written;
      struct sockaddr_un addr;
      char response[1]; // OpenSSL error code, e.g.: X509_V_OK, X509_V_ERR_CERT_REVOKED, etc.

      // SOCK_SEQPACKET notes:
      // - Connection-oriented socket (like SOCK_STREAM), but preserving message boundaries (like SOCK_DGRAM)
      // - Reads and writes are atomic (no partial reads or writes)
      if((fd = socket(AF_UNIX, SOCK_SEQPACKET, 0)) < 0)
      {
          msg_notice("Could not create socket to external validator");
          goto out_error;
      }

      memset(&addr, 0, sizeof(addr));
      addr.sun_family = AF_UNIX;
      strcpy(addr.sun_path, custom_peer_certificate_validation);

      if(connect(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0)
      {
          msg_notice("Could not bind socket to external validator");
          goto sock_error;
      }

      {
          // Write socket with timeout.
          // Currently, waiting for maximum 15 seconds.
          fd_set wfds;
          struct timeval timeout = {15, 0};
          int sel_ret;

          FD_ZERO(&wfds);
          FD_SET(fd, &wfds);

          sel_ret = Select(fd + 1, NULL, &wfds, NULL, &timeout);

          if(sel_ret < 0)
          {
              msg_notice("Error while sending request to external validator");
              goto sock_error;
          }
          else if(sel_ret == 0)
          {
              msg_notice("Timeout reached while waiting for external validator");
              goto sock_error;
          }

          // Write depth byte first.
          written = write(fd, depth, 1);
          if(written <= 0)
          {
              msg_notice("Could not write certificate depth to external validator");
              goto sock_error;
          }

          written = write(fd, pData, bytesAvailable);
          if(written <= 0)
          {
              msg_notice("Could not write certificate bytes to external validator");
              goto sock_error;
          }
      }

      {
          // Read socket with timeout.
          // Currently, waiting for maximum 15 seconds.
          fd_set rfds;
          struct timeval timeout = {15, 0};
          int sel_ret;

          FD_ZERO(&rfds);
          FD_SET(fd, &rfds);
          sel_ret = Select(fd + 1, &rfds, NULL, NULL, &timeout);

          if(sel_ret < 0)
          {
              msg_notice("Error while waiting for response from external validator");
              goto sock_error;
          }
          else if(sel_ret == 0)
          {
              msg_notice("Timeout reached while waiting for external validator");
              goto sock_error;
          }
      }

      if(read(fd, response, sizeof(response)) <= 0)
      {
          msg_notice("Error reading response from external validator");
          goto sock_error;
      }

      errorCode = (int)response[0];

      if(errorCode != X509_V_OK)
      {
          X509_STORE_CTX_set_error(ctx, errorCode);
          msg_notice("Certificate not accepted", evt_tag_str("error-code", X509_verify_cert_error_string(errorCode)));
          goto sock_error;
      }
  }

msg_notice("Certificate accepted");

close(fd);
BIO_free(bio);

return TRUE;

sock_error:
  close(fd); // fall-through

out_error:
  BIO_free(bio);

  return FALSE;
}
