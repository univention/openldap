/* $OpenLDAP: Exp $ */
/*
 * Copyright 2003 Steve Langasek
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 * gnutls.c - Compatibility wrapper for calling GNU TLS with the OpenSSL API
 */

#include "portable.h"
#include "ldap_config.h"

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h> /* for GCRY_THREAD_OPTION_PTHREAD_IMPL */
#include <pthread.h> /* for GCRY_THREAD_OPTION_PTHREAD_IMPL */

#include <ac/stdlib.h>
#include <ac/string.h>
#include <ac/ctype.h>
#include <ac/unistd.h>

#include "ldap-int.h"

#ifdef HAVE_GNUTLS_GNUTLS_H

#include <gnutls/gnutls.h>
#include <gcrypt.h>
#include "ldap_pvt_gnutls.h"

/* needs GNUTLS 1.0.9 */
GCRY_THREAD_OPTION_PTHREAD_IMPL;

/* XXX: who designed this lousy API? */
static int gnutls_error = 0;

#define DH_BITS      768
#define RSA_BITS     512

int
ERR_get_error(void)
{
	int ret = (gnutls_error * -1);
	gnutls_error = 0;
	return ret;
}

int
ERR_peek_error(void)
{
	return (gnutls_error * -1);
}

const char *
ERR_error_string(int errnum, char *buf)
{
	return gnutls_strerror(errnum * -1);
}

const char *
ERR_error_string_n(int errnum, char *buf, int buflen)
{
	const char *tmpbuf = gnutls_strerror(errnum);
	if (buf && tmpbuf) {
		strncpy(buf,tmpbuf,buflen-1);
		buf[buflen-1] = '\0';
	}
	return tmpbuf;
}

unsigned long
ERR_get_error_line(const char **file, int *line)
{
	int ret;

	*file = NULL;
	*line = 0;
	ret = gnutls_error;
	gnutls_error = 0;
	return ret;
}

BIO *
BIO_new( BIO_METHOD *method )
{
	BIO *bio = malloc(sizeof(*bio));

	if (!bio)
		return NULL;

	if (method->create) {
		if (!method->create(bio) || !bio->init) {
			free(bio);
			return NULL;
		}
	}
	bio->init = 1;
	bio->method = method;
	return bio;
}

/* These are handled by the gnutls_deinit() function; trying to free
   them directly yields a segfault. */
void X509_free(void *ptr) {
	return;
}

X509_NAME *
X509_get_subject_name( const X509 *x )
{
	X509_NAME *dn = NULL;

	if (!x)
		return NULL;

	if (!(dn = malloc(sizeof(*dn))))
		return NULL;

	if (gnutls_x509_extract_certificate_dn( x, dn )) {
		free(dn);
		return NULL;
	}

	return dn;
}

X509_NAME *
X509_get_issuer_name( const X509 *x )
{
	X509_NAME *dn = NULL;

	if (!x)
		return NULL;

	if (!(dn = malloc(sizeof(*dn))))
		return NULL;

	if (gnutls_x509_extract_certificate_issuer_dn( x, dn )) {
		free(dn);
		return NULL;
	}

	return dn;
}

char *
X509_NAME_oneline( X509_NAME *dn, char *buf, int buflen )
{
	if (!dn)
		return NULL;

	if (!buf) {
		buflen = strlen(dn->country)
		         + strlen(dn->state_or_province_name)
		         + strlen(dn->locality_name)
		         + strlen(dn->organization)
		         + strlen(dn->organizational_unit_name)
		         + strlen(dn->common_name) + strlen(dn->email)
		         + 33;
		buf = (char *)malloc(buflen);
	}
	if (!buf)
		return NULL;

	snprintf(buf, buflen, "C=%s, ST=%s, L=%s, O=%s, OU=%s, CN=%s/Email=%s",
	         dn->country, dn->state_or_province_name, dn->locality_name,
	         dn->organization, dn->organizational_unit_name,
	         dn->common_name, dn->email);
	buf[buflen-1] = '\0';
	return buf;
}

const char *
X509_verify_cert_error_string( int errnum )
{
	switch (errnum) {
	case GNUTLS_CERT_INVALID:
		return "Certificate is invalid";
	case GNUTLS_CERT_REVOKED:
		return "Certificate has been revoked";
	case 0:
		return "No error";
	default:
		return "Unknown error";
	}
}

const X509 *
X509_STORE_CTX_get_current_cert( X509_STORE_CTX *ctx )
{
	if (!ctx)
		return NULL;
	return ctx->cert_list;
}

int
X509_STORE_CTX_get_error( X509_STORE_CTX *ctx )
{
	if (!ctx)
		return -1;
	return ctx->error;
}

int
X509_STORE_CTX_get_error_depth( X509_STORE_CTX *ctx )
{
	/* XXX: gnutls doesn't seem to track CA chain depth. */
	return 0;
}

int
SSLeay_add_ssl_algorithms(void)
{
	/* XXX: is add_ssl_algorithms really a good place for this? */
	
	/* needs GNUTLS 1.0.9 */
	gcry_control (GCRYCTL_SET_THREAD_CBS, &gcry_threads_pthread);

	if ((gnutls_error = gnutls_global_init()) < 0) {
		return 0;
	}
	return 1;
}

SSL_METHOD *
SSLv23_method() {
	SSL_METHOD *method;

	method = calloc(1, sizeof(*method));
	if (!method)
		return NULL;

	method->protocol_priority[0] = GNUTLS_TLS1;
	method->protocol_priority[1] = GNUTLS_SSL3;
	method->protocol_priority[2] = 0;

	method->cipher_priority[0] = GNUTLS_CIPHER_RIJNDAEL_128_CBC;
	method->cipher_priority[1] = GNUTLS_CIPHER_3DES_CBC;
	method->cipher_priority[2] = GNUTLS_CIPHER_RIJNDAEL_256_CBC;
	method->cipher_priority[3] = GNUTLS_CIPHER_ARCFOUR_128;
	method->cipher_priority[4] = 0;

	method->comp_priority[0] = GNUTLS_COMP_ZLIB;
	method->comp_priority[1] = GNUTLS_COMP_NULL;
	method->comp_priority[2] = 0;

	method->kx_priority[0] = GNUTLS_KX_DHE_RSA;
	method->kx_priority[1] = GNUTLS_KX_RSA;
	method->kx_priority[2] = GNUTLS_KX_DHE_DSS;
	method->kx_priority[3] = 0;

	method->mac_priority[0] = GNUTLS_MAC_SHA;
	method->mac_priority[1] = GNUTLS_MAC_MD5;
	method->mac_priority[2] = 0;

	return method;
}

void
SSL_CTX_free( SSL_CTX *ctx )
{
	if (!ctx)
		return;

	if (ctx->creds)
		gnutls_certificate_free_credentials(ctx->creds);
	if (ctx->method)
		free(ctx->method);
	free(ctx);

	/* XXX: this *really* doesn't belong here, but in practice,
	   we're using a global context anyway. */
	gnutls_global_deinit();
}

SSL_CTX *
SSL_CTX_new( SSL_METHOD *method )
{
	SSL_CTX *ctx = NULL;

	ctx = calloc(1,sizeof(*ctx));
	if (ctx)
		ctx->method = method;

	return ctx;
}

int
SSL_CTX_set_cipher_list( SSL_CTX *ctx, char *ciphersuite )
{
	/* XXX: GNUTLS seems to ignore this; we will, too; but
	   it should be handled by converting the string to a
	   prioritized cipher list. */
	return 1;
}

/* These we ignore because I don't see that they do anything useful. */
int
SSL_CTX_load_verify_locations( SSL_CTX *ctx, const char *CAfile,
                               const char *CApath )
{
	return 1;
}

int
SSL_CTX_set_default_verify_paths( SSL_CTX *ctx )
{
	return 1;
}

int
SSL_CTX_set_session_id_context( SSL_CTX *ctx, const unsigned char *sid_ctx,
                                unsigned int sid_ctx_len )
{
	return 1;
}

void
SSL_CTX_set_client_CA_list( SSL_CTX *ctx,
                            gnutls_certificate_credentials calist )
{
	if (!ctx)
		return;

	if (ctx->creds) {
		gnutls_certificate_free_credentials(ctx->creds);
	}
	ctx->creds = calist;
}

static int
write_datum(int fd, gnutls_datum *d)
{
	if (write(fd, &(d->size), sizeof(d->size)) != sizeof(d->size)) return 0;
	if (write(fd, d->data, d->size) != d->size) return 0;
	return 1;
}


static int
read_datum(int fd, gnutls_datum *d)
{
	if (read(fd, &(d->size), sizeof(d->size)) != sizeof(d->size)) return 0;
	d->data = malloc(d->size);
	if (d->data == NULL) return 0;
	if (read(fd, d->data, d->size) != d->size) return 0;
	return 1;
}

static gnutls_rsa_params
tls_gnutls_need_rsa_params(void)
{
	static const char cache_name[] = "/var/run/slapd/params_cache_rsa";
	gnutls_rsa_params rsa_params = NULL;
	int cache_fd;
	int bits = RSA_BITS;
	gnutls_datum m, e, d, p, q, u;
	int read_ok = 0;

	/* Initialize the RSA parameters */
	gnutls_error = gnutls_rsa_params_init(&rsa_params);
	if (gnutls_error < 0) {
#ifdef NEW_LOGGING
		LDAP_LOG ( TRANSPORT, ERR,
		    "init_rsa_dh: TLS: gnutls_rsa_params_init failed.\n",0,0,0);
#else
		Debug ( LDAP_DEBUG_ANY,
		    "init_rsa_dh: TLS: gnutls_rsa_params_init failed.\n",0,0,0);
#endif
		return NULL;
	}

	cache_fd = open(cache_name,O_RDONLY,0);
	if (cache_fd != -1) {

		/* read_datum will allocate memory for X.data, we need to free it later */
		if (read_datum(cache_fd, &m) &&
		    read_datum(cache_fd, &e) &&
		    read_datum(cache_fd, &d) &&
		    read_datum(cache_fd, &p) &&
		    read_datum(cache_fd, &q) &&
		    read_datum(cache_fd, &u)) {

			read_ok = 1;

			gnutls_error = gnutls_rsa_params_import_raw(rsa_params, &m, &e, &d, &p, &q, &u);

			/* Free the data parts which read_datum allocated */
			free(m.data);
			free(e.data);
			free(d.data);
			free(p.data);
			free(q.data);
			free(u.data);

		} else {
			read_ok = -1;
		}
		close(cache_fd);
	}

	if (read_ok <= 0) {
		char temp_cache_name[sizeof(cache_name) + 10];

		/* Not able to read from the file so we generate new parameters */
		gnutls_error = gnutls_rsa_params_generate2(rsa_params, RSA_BITS);
		if (gnutls_error < 0) return gnutls_error;

		/* gnutls_rsa_params_export_raw will allocate the memory for the params */
		gnutls_error = gnutls_rsa_params_export_raw(rsa_params, &m, &e, &d, &p, &q, &u, &bits);
		if (gnutls_error < 0) return gnutls_error;
		sprintf(temp_cache_name, "%s-%d", cache_name, (int) getpid());

		/* Ignore errors... Not everybody has /var/run/slapd/ world writeable... */
		unlink(temp_cache_name);
		cache_fd = open(temp_cache_name, O_WRONLY|O_CREAT|O_EXCL, 0600);
		if (cache_fd != -1) {
			int ren;

			ren = write_datum(cache_fd, &m) &&
			      write_datum(cache_fd, &e) &&
			      write_datum(cache_fd, &d) &&
			      write_datum(cache_fd, &p) &&
			      write_datum(cache_fd, &q) &&
			      write_datum(cache_fd, &u);

			close(cache_fd);
			if (ren) {
				rename(temp_cache_name, cache_name);
			}
		}

		/* Free the parameters that are allocated by gnutls_rsa_params_export_raw */
		gnutls_free(m.data);
		gnutls_free(e.data);
		gnutls_free(d.data);
		gnutls_free(p.data);
		gnutls_free(q.data);
		gnutls_free(u.data);
	}

	return rsa_params;
}

static gnutls_dh_params
tls_gnutls_need_dh_params(void)
{
	static const char cache_name[] = "/var/run/slapd/params_cache_dh";
	gnutls_dh_params dh_params = NULL;
	int cache_fd, bits = DH_BITS;
	gnutls_datum prime, generator;
	int read_ok = 0;

	/* Initialize the DH parameters */
	gnutls_error = gnutls_dh_params_init(&dh_params);
	if (gnutls_error < 0) {
#ifdef NEW_LOGGING
		LDAP_LOG ( TRANSPORT, ERR,
		    "init_rsa_dh: TLS: gnutls_dh_params_init failed.\n",0,0,0);
#else			
		Debug ( LDAP_DEBUG_ANY,
		    "init_rsa_dh: TLS: gnutls_dh_params_init failed.\n",0,0,0);
#endif
		return NULL;
	}

	cache_fd = open(cache_name,O_RDONLY,0);
	if (cache_fd != -1) {

		/* read_datum will allocate X.data, need to free it later */
		if (read_datum(cache_fd, &prime) &&
		    read_datum(cache_fd, &generator)) {

			read_ok = 1;

			gnutls_dh_params_import_raw(dh_params,&prime,&generator);

			/* Free the .data's allocated by read_datum */
			free(prime.data);
			free(generator.data);
		} else {
			read_ok = -1;
		}
		close(cache_fd);
	}
	if (read_ok <= 0) {
		char temp_cache_name[sizeof(cache_name) + 10];

		gnutls_error = gnutls_dh_params_generate2(dh_params, DH_BITS);
		if (gnutls_error < 0) return gnutls_error;

		gnutls_error = gnutls_dh_params_export_raw(dh_params, &prime, &generator, &bits);
		if (gnutls_error < 0) return gnutls_error;
		sprintf(temp_cache_name, "%s-%d", cache_name, (int) getpid());

		/* Ignore errors... Not everybody has /var/run/slapd/ world writeable... */
		unlink(temp_cache_name);
		cache_fd = open(temp_cache_name, O_WRONLY|O_CREAT|O_EXCL, 0600);
		if (cache_fd != -1) {
			int ren;

			ren = write_datum(cache_fd, &prime) &&
			      write_datum(cache_fd, &generator);

			close(cache_fd);

			if (ren) {
				rename(temp_cache_name, cache_name);
			}
		}

		gnutls_free(prime.data);
		gnutls_free(generator.data);
	}
	
	return dh_params;
}

int
tls_gnutls_params_cb( gnutls_session session, gnutls_params_type type, 
		gnutls_params_st *st )
{
	if (type == GNUTLS_PARAMS_RSA_EXPORT) {
		st->params.rsa_export = tls_gnutls_need_rsa_params();
		if (st->params.rsa_export == NULL) return -1;
	} else if (type == GNUTLS_PARAMS_DH) {
		st->params.dh = tls_gnutls_need_dh_params();
		if (st->params.dh == NULL) return -1;
	} else return -1;

	st->type = type;
	st->deinit = 1;

	return 0;
}
#if 0 /* use this for GNUTLS < 1.0.9 */
void
tls_gnutls_set_params( gnutls_certificate_credentials cred )
{
	gnutls_rsa_params rsa_params = tls_gnutls_need_rsa_params();
	gnutls_dh_params dh_params = tls_gnutls_need_dh_params();

	gnutls_certificate_set_rsa_export_params( cred, rsa_params );
	gnutls_certificate_set_dh_params( cred, dh_params );
}
#endif


void
SSL_CTX_set_verify( SSL_CTX *ctx, int mode,
                    int (*verify_callback)(int, X509_STORE_CTX *) )
{
	if (!ctx)
		return;

	ctx->verify_mode = mode;
	ctx->verify_callback = verify_callback;
}

SSL *
SSL_new( SSL_CTX * ctx )
{
	SSL *ssl = calloc(1,sizeof(*ssl));

	if (!ssl) {
		gnutls_error = GNUTLS_E_MEMORY_ERROR;
		return NULL;
	}

	ssl->session = NULL;

	if (ctx) {
		ssl->verify_mode = ctx->verify_mode;
		ssl->verify_callback = ctx->verify_callback;
		ssl->creds = ctx->creds;
		ssl->method = ctx->method;
	}
	return ssl;
}

void
SSL_free( SSL *ssl )
{
	if (!ssl) {
		gnutls_error = GNUTLS_E_INVALID_SESSION;
		return;
	}

	if (ssl->session)
		gnutls_deinit(ssl->session);

	free(ssl);
}

static int
SSL_do_handshake( SSL *ssl, gnutls_connection_end end )
{
	int cert_list_length;
	int ret;
	const gnutls_datum *cert_list;
	X509_STORE_CTX *x509_store;

	/* Initialize the session here, not in SSL_new(), because this
	   is the first place we know which side of the connection we're
	   on. */
	if (!ssl->session) {
		if ((gnutls_error = gnutls_init(&ssl->session, end)) < 0)
		{
			return 0;
		}

		gnutls_protocol_set_priority(ssl->session,
		                             ssl->method->protocol_priority);
		gnutls_cipher_set_priority(ssl->session,
		                           ssl->method->cipher_priority);
		gnutls_compression_set_priority(ssl->session,
		                                ssl->method->comp_priority);
		gnutls_kx_set_priority(ssl->session, ssl->method->kx_priority);
		gnutls_mac_set_priority(ssl->session,
		                        ssl->method->mac_priority);

		gnutls_transport_set_ptr2(ssl->session,
		                          (gnutls_transport_ptr)ssl->rbio,
		                          (gnutls_transport_ptr)ssl->wbio);

		if (ssl->rbio && ssl->rbio->init) {
			gnutls_transport_set_pull_function(ssl->session,
			                                   ssl->rbio->method->read);
		}

		if (ssl->wbio && ssl->wbio->init) {
			gnutls_transport_set_push_function(ssl->session,
			                                   ssl->wbio->method->write);
		}

		/* TODO: parse the cipher list OpenSSL uses, and import it
		   to a cipher_priority list. */

		/* Ignore any failures here; maybe we can get by without
		   any credentials at all? Or should we only ignore errors
		   if we don't require ca verification? */
		gnutls_credentials_set(ssl->session, GNUTLS_CRD_CERTIFICATE, 
		                       ssl->creds);
	}

	gnutls_error = gnutls_handshake(ssl->session);
	if (gnutls_error < 0)
		return gnutls_error;

	cert_list = gnutls_certificate_get_peers(ssl->session,
	                                         &cert_list_length);

	ret = gnutls_certificate_verify_peers(ssl->session);

	x509_store = malloc(sizeof(*x509_store));
	if (x509_store) {
		x509_store->ssl = ssl;
		x509_store->cert_list = cert_list;
		x509_store->error = ret;
	}

	/* The callback wants a boolean, not an error code. */
	ssl->verify_result = !ret;

	if (ssl->verify_callback)
		ssl->verify_result = ssl->verify_callback(ssl->verify_result,
							  x509_store);

	free(x509_store);

	if (!ssl->verify_result && ssl->verify_mode != SSL_VERIFY_NONE)
	{
		gnutls_error = GNUTLS_E_CERTIFICATE_ERROR;
		return 0;
	}

	return 1;
}

int
SSL_accept( SSL *ssl )
{
	return SSL_do_handshake(ssl, GNUTLS_SERVER);
}

int
SSL_connect( SSL *ssl )
{
	return SSL_do_handshake(ssl, GNUTLS_CLIENT);
}

int
SSL_shutdown( SSL *ssl)
{
	if (!ssl || !ssl->session) {
		gnutls_error = GNUTLS_E_INVALID_SESSION;
		return 0;
	}
	gnutls_error = gnutls_bye(ssl->session, GNUTLS_SHUT_RDWR);
	return (!gnutls_error);
}

int
SSL_pending( SSL *ssl )
{
	if (!ssl)
		return 0;
	return gnutls_record_check_pending(ssl->session);
}

int
SSL_read( SSL *ssl, void *buf, int buflen )
{
	int ret;

	if (!ssl) {
		gnutls_error = GNUTLS_E_INVALID_SESSION;
		return 0;
	}
	ret = gnutls_read(ssl->session, buf, buflen);
	if (ret < 0)
		gnutls_error = ret;

	return ret;
}


int
SSL_write( SSL *ssl, const void *buf, int buflen )
{
	int ret;

	if (!ssl) {
		gnutls_error = GNUTLS_E_INVALID_SESSION;
		return 0;
	}
	ret = gnutls_write(ssl->session, buf, buflen);
	if (ret < 0)
		gnutls_error = ret;

	return ret;
}

int
SSL_get_error( SSL *ssl, int ret )
{
	/* XXX: aren't these the same errors returned by read? */
	if (ret == GNUTLS_E_AGAIN || ret == GNUTLS_E_INTERRUPTED)
		return SSL_ERROR_WANT_WRITE;
	/* This should only happen on read; we ignore it, because we
	   have no sane way to react to it. */
	if (ret == GNUTLS_E_WARNING_ALERT_RECEIVED)
		return SSL_ERROR_WANT_READ;

	return SSL_ERROR_NONE;
}

SSL_CIPHER *
SSL_get_current_cipher( SSL *ssl )
{
	ssl->cipher = gnutls_cipher_get(ssl->session);
	return &ssl->cipher;
}

int
SSL_CIPHER_get_bits(SSL_CIPHER *cipher, int *alg_bits)
{
	int bits;

	if (!cipher)
		return 0;

	bits = gnutls_cipher_get_key_size(*cipher) * 8;

	if (alg_bits)
		*alg_bits = bits;

	return bits;
}

X509 *
SSL_get_certificate( SSL *ssl )
{
	if (!ssl) {
		gnutls_error = GNUTLS_E_INVALID_SESSION;
		return NULL;
	}
	return (X509 *)gnutls_certificate_get_ours(ssl->session);
}

X509 *
SSL_get_peer_certificate( SSL *ssl )
{
	int list_size = 0;

	if (!ssl) {
		gnutls_error = GNUTLS_E_INVALID_SESSION;
		return NULL;
	}
	return (X509 *)gnutls_certificate_get_peers(ssl->session, &list_size);
}

int 
SSL_get_verify_result( SSL *ssl )
{
	if (!ssl) {
		gnutls_error = GNUTLS_E_INVALID_SESSION;
		return 1;
	}
	/* XXX: why does the meaning of this keep switching? :P */
	return !ssl->verify_result;
}

void
SSL_set_bio( SSL *ssl, BIO *rbio, BIO *wbio )
{
	gnutls_error = GNUTLS_E_SUCCESS;

	if (!ssl) {
		gnutls_error = GNUTLS_E_INVALID_SESSION;
		return;
	}

	/* This may be called before we have all the pieces to set up
	   the session. */
	ssl->rbio = rbio;
	ssl->wbio = wbio;

	if (ssl->session) {
		gnutls_transport_set_ptr2(ssl->session,
		                          (gnutls_transport_ptr)rbio,
		                          (gnutls_transport_ptr)wbio);

		if (rbio && rbio->init) {
			gnutls_transport_set_pull_function(ssl->session,
			                                   rbio->method->read);
		}

		if (wbio && wbio->init) {
			gnutls_transport_set_push_function(ssl->session,
			                                   wbio->method->write);
		}
	}
}

#endif

