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
 * ldap_pvt_gnutls.h - headers for the internal GNUTLS/OpenSSL wrapper
 */

#ifndef _LDAP_PVT_GNUTLS_H
#define _LDAP_PVT_GNUTLS_H

#ifdef HAVE_GNUTLS_GNUTLS_H
#include <gnutls/gnutls.h>


#define BIO_CTRL_FLUSH		11 /* Doesn't matter, we never use this. */

#define BIO_FLAGS_READ		0x01
#define BIO_FLAGS_WRITE		0x02
#define BIO_FLAGS_IO_SPECIAL	0x04
#define BIO_FLAGS_RWS		(BIO_FLAGS_READ|BIO_FLAGS_WRITE|BIO_FLAGS_IO_SPECIAL)
#define BIO_FLAGS_SHOULD_RETRY	0x08

#define BIO_set_flags(b,f) ((b)->flags|=(f))
#define BIO_get_flags(b) ((b)->flags)
#define BIO_set_retry_special(b) \
		((b)->flags|=(BIO_FLAGS_IO_SPECIAL|BIO_FLAGS_SHOULD_RETRY))
#define BIO_set_retry_read(b) \
		((b)->flags|=(BIO_FLAGS_READ|BIO_FLAGS_SHOULD_RETRY))
#define BIO_set_retry_write(b) \
		((b)->flags|=(BIO_FLAGS_WRITE|BIO_FLAGS_SHOULD_RETRY))

/* These are normally used internally in BIOs */
#define BIO_clear_flags(b,f) ((b)->flags&= ~(f))
#define BIO_clear_retry_flags(b) \
		((b)->flags&= ~(BIO_FLAGS_RWS|BIO_FLAGS_SHOULD_RETRY))
#define BIO_get_retry_flags(b) \
		((b)->flags&(BIO_FLAGS_RWS|BIO_FLAGS_SHOULD_RETRY))

#define SSL_VERIFY_NONE			0x00
#define SSL_VERIFY_PEER			0x01
#define SSL_VERIFY_FAIL_IF_NO_PEER_CERT	0x02
#define SSL_VERIFY_CLIENT_ONCE		0x04

#define SSL_ERROR_NONE			0
#define SSL_ERROR_WANT_READ		2
#define SSL_ERROR_WANT_WRITE		3
#define SSL_ERROR_WANT_CONNECT		7

#define SSL3_AL_WARNING			GNUTLS_AL_WARNING
#define SSL3_AD_BAD_CERTIFICATE		GNUTLS_A_BAD_CERTIFICATE

#define ssl3_send_alert(ssl, level, type) gnutls_alert_send((ssl)->session, \
								level, type);

/* These are no-ops; just define them away. */
#define SSL_load_error_strings() /* */
#define X509V3_add_standard_extensions() /* */
#define EVP_cleanup() /* */
#define ERR_free_strings() /* */

#define CRYPTO_free(x) free(x)


typedef struct X509_STORE_CTX {
    struct SSL *ssl;
    int error;
    const gnutls_datum *cert_list;
} X509_STORE_CTX;

/* Kludge: we don't really care about the semantics of OpenSSL stacks,
   we just need to map STACK_OF(X509_NAME) to something unique so we can
   typedef to the GNUTLS equivalent. */
#define STACK_OF(x) x##_st

typedef struct DSTRUCT X509_NAME_st;
typedef gnutls_x509_dn X509_NAME;
typedef gnutls_datum X509;

typedef struct bio_decl BIO;

typedef struct BIO_METHOD {
	int type;
	char *desc;
	ssize_t (*write)(gnutls_transport_ptr, const void *, size_t);
	ssize_t (*read)(gnutls_transport_ptr, void *, size_t);
	int (*puts)(BIO *, const char *);
	int (*gets)(BIO *, char *, int);
	long (*ctrl)(BIO *, int, long, void *);
	int (*create)(BIO *);
	int (*destroy)(BIO *);
} BIO_METHOD;

struct bio_decl {
    BIO_METHOD *method;
    int init;
    int num;
    void *ptr;
    int flags;
};

typedef struct
{
    int protocol_priority[GNUTLS_MAX_ALGORITHM_NUM];
    int cipher_priority[GNUTLS_MAX_ALGORITHM_NUM];
    int comp_priority[GNUTLS_MAX_ALGORITHM_NUM];
    int kx_priority[GNUTLS_MAX_ALGORITHM_NUM];
    int mac_priority[GNUTLS_MAX_ALGORITHM_NUM];
    gnutls_connection_end connend;
} SSL_METHOD;

typedef struct SSL_CTX {
	gnutls_certificate_credentials creds;
	SSL_METHOD *method;
	int verify_mode;
	int (*verify_callback)(int, X509_STORE_CTX *);
} SSL_CTX;

/* This structure corresponds to the per-session state */
typedef struct SSL {
	gnutls_session session;
	gnutls_cipher_algorithm cipher;
	SSL_METHOD *method;
	int verify_mode;
	int (*verify_callback)(int, X509_STORE_CTX *);
	int verify_result;
	BIO *rbio;
	BIO *wbio;
	gnutls_certificate_credentials creds;
} SSL;

typedef gnutls_cipher_algorithm SSL_CIPHER;


/* Mangle the function names, to prevent collisions with other functions
   of the same name loaded by other libraries (i.e., OpenSSL) */
#define ERR_get_error gnutls_ERR_get_error
#define ERR_peek_error gnutls_ERR_peek_error
#define ERR_error_string gnutls_ERR_error_string
#define ERR_error_string_n gnutls_ERR_error_string_n
#define ERR_get_error_line gnutls_ERR_get_error_line
#define BIO_new gnutls_BIO_new
#define X509_free gnutls_X509_free
#define X509_get_subject_name gnutls_X509_get_subject_name
#define X509_get_issuer_name gnutls_X509_get_issuer_name
#define X509_NAME_oneline gnutls_X509_NAME_oneline
#define X509_verify_cert_error_string gnutls_X509_verify_cert_error_string
#define X509_STORE_CTX_get_current_cert gnutls_X509_STORE_CTX_get_current_cert 
#define X509_STORE_CTX_get_error gnutls_X509_STORE_CTX_get_error
#define X509_STORE_CTX_get_error_depth gnutls_X509_STORE_CTX_get_error_depth
#define SSLeay_add_ssl_algorithms gnutls_SSLeay_add_ssl_algorithms
#define SSLv23_method gnutls_SSLv23_method
#define SSL_CIPHER_get_bits gnutls_SSL_CIPHER_get_bits
#define SSL_CTX_free gnutls_SSL_CTX_free
#define SSL_CTX_load_verify_locations gnutls_SSL_CTX_load_verify_locations
#define SSL_CTX_new gnutls_SSL_CTX_new
#define SSL_CTX_set_cipher_list gnutls_SSL_CTX_set_cipher_list
#define SSL_CTX_set_client_CA_list gnutls_SSL_CTX_set_client_CA_list
#define SSL_CTX_set_default_verify_paths gnutls_SSL_CTX_set_default_verify_paths
#define SSL_CTX_set_session_id_context gnutls_SSL_CTX_set_session_id_context
#define SSL_CTX_set_verify gnutls_SSL_CTX_set_verify
#define SSL_accept gnutls_SSL_accept
#define SSL_connect gnutls_SSL_connect
#define SSL_free gnutls_SSL_free
#define SSL_get_certificate gnutls_SSL_get_certificate
#define SSL_get_current_cipher gnutls_SSL_get_current_cipher
#define SSL_get_error gnutls_SSL_get_error
#define SSL_get_peer_certificate gnutls_SSL_get_peer_certificate
#define SSL_get_verify_result gnutls_SSL_get_verify_result
#define SSL_new gnutls_SSL_new
#define SSL_pending gnutls_SSL_pending
#define SSL_read gnutls_SSL_read
#define SSL_set_bio gnutls_SSL_set_bio
#define SSL_shutdown gnutls_SSL_shutdown
#define SSL_write gnutls_SSL_write

int ERR_get_error(void);
int ERR_peek_error(void);
const char *ERR_error_string(int errnum, char *buf);
const char *ERR_error_string_n(int errnum, char *buf, int buflen);
unsigned long ERR_get_error_line(const char **file, int *line);

BIO *BIO_new( BIO_METHOD *method );

void X509_free(void *ptr);
X509_NAME *X509_get_subject_name( const X509 *x );
X509_NAME *X509_get_issuer_name( const X509 *x );
char *X509_NAME_oneline( X509_NAME *dn, char *buf, int buflen );
const char *X509_verify_cert_error_string( int errnum );
const X509 *X509_STORE_CTX_get_current_cert( X509_STORE_CTX *ctx );
int X509_STORE_CTX_get_error( X509_STORE_CTX *ctx );
int X509_STORE_CTX_get_error_depth( X509_STORE_CTX *ctx );

int SSLeay_add_ssl_algorithms(void);
SSL_METHOD *SSLv23_method();
void SSL_CTX_free( SSL_CTX *ctx );
SSL_CTX *SSL_CTX_new( SSL_METHOD *method );
int SSL_CTX_set_cipher_list( SSL_CTX *ctx, char *ciphersuite );
int SSL_CTX_load_verify_locations( SSL_CTX *ctx, const char *CAfile,
                                   const char *CApath );
int SSL_CTX_set_default_verify_paths( SSL_CTX *ctx );
int SSL_CTX_set_session_id_context( SSL_CTX *ctx, const unsigned char *sid_ctx,
                                    unsigned int sid_ctx_len );
void SSL_CTX_set_client_CA_list( SSL_CTX *ctx,
                                 gnutls_certificate_credentials calist );
void SSL_CTX_set_verify( SSL_CTX *ctx, int mode,
                         int (*verify_callback)(int, X509_STORE_CTX *) );

SSL *SSL_new( SSL_CTX * ctx );
void SSL_free( SSL *ssl );
int SSL_accept( SSL *ssl );
int SSL_connect( SSL *ssl );
int SSL_shutdown( SSL *ssl);
int SSL_pending( SSL *ssl );
int SSL_read( SSL *ssl, void *buf, int buflen );
int SSL_write( SSL *ssl, const void *buf, int buflen );
int SSL_get_error( SSL *ssl, int ret );
SSL_CIPHER *SSL_get_current_cipher( SSL *ssl );
int SSL_CIPHER_get_bits(SSL_CIPHER *cipher, int *alg_bits);
X509 *SSL_get_certificate( SSL *ssl );
X509 *SSL_get_peer_certificate( SSL *ssl );
int SSL_get_verify_result( SSL *ssl );
void SSL_set_bio( SSL *ssl, BIO *rbio, BIO *wbio );

void ldap_gnutls_need_rsa_params(gnutls_certificate_credentials creds);
void ldap_gnutls_need_dh_params(gnutls_certificate_credentials creds);
#endif
#endif
