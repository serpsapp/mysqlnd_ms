/*
  +----------------------------------------------------------------------+
  | PHP Version 5                                                        |
  +----------------------------------------------------------------------+
  | Copyright (c) 1997-2013 The PHP Group                                |
  +----------------------------------------------------------------------+
  | This source file is subject to version 3.01 of the PHP license,      |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.php.net/license/3_01.txt                                  |
  | If you did not receive a copy of the PHP license and are unable to   |
  | obtain it through the world-wide-web, please send a note to          |
  | license@php.net so we can mail you a copy immediately.               |
  +----------------------------------------------------------------------+
  | Author: Andrey Hristov <andrey@php.net>                              |
  |         Ulf Wendel <uw@php.net>                                      |
  |         Johannes Schlueter <johannes@php.net>                        |
  +----------------------------------------------------------------------+
*/

#include "zend.h"
#include "zend_alloc.h"
#include "zend_interfaces.h"
#include "main/php.h"
#include "main/spprintf.h"
#include "main/php_streams.h"

#include "mysqlnd_fabric.h"
#include "mysqlnd_fabric_priv.h"

php_stream *mysqlnd_fabric_handle_digest_auth(php_stream *stream, char* username, char* password);

char *mysqlnd_fabric_http(mysqlnd_fabric *fabric, char *url, char *request_body, size_t request_body_len, size_t *response_len)
{
	char *retval;
	char *rpc_url;
	zval method, content, header, ignore_errors;
	php_stream_context *ctxt;
	php_stream *stream = NULL;

	TSRMLS_FETCH();
	
	ZVAL_STRINGL(&method, "POST", sizeof("POST")-1, 0);
	ZVAL_STRINGL(&content, request_body, request_body_len, 0);
	ZVAL_STRINGL(&header, "Content-Type: text/xml", sizeof("Content-Type: text/xml")-1, 0);
	ZVAL_BOOL(&ignore_errors, 1);
	
	/* prevent anybody from freeing these */
	Z_SET_ISREF(method);
	Z_SET_ISREF(content);
	Z_SET_ISREF(header);
	Z_SET_ISREF(ignore_errors);
	Z_SET_REFCOUNT(method, 2);
	Z_SET_REFCOUNT(content, 2);
	Z_SET_REFCOUNT(header, 2);
	Z_SET_REFCOUNT(ignore_errors, 2);
	
	ctxt = php_stream_context_alloc(TSRMLS_C);
	php_stream_context_set_option(ctxt, "http", "method", &method);
	php_stream_context_set_option(ctxt, "http", "content", &content);
	php_stream_context_set_option(ctxt, "http", "header", &header);
	php_stream_context_set_option(ctxt, "http", "ignore_errors", &ignore_errors);

	rpc_url = malloc(strlen(url) + 5);
	snprintf(rpc_url, strlen(url) + 5, "%sRPC2", url);
	/* TODO: Switch to quiet mode? */
	stream = php_stream_open_wrapper_ex(rpc_url, "rb", REPORT_ERRORS, NULL, ctxt);
	stream = mysqlnd_fabric_handle_digest_auth(stream, fabric->hosts[0].username, fabric->hosts[0].password);
	free(rpc_url);

	if (!stream) {
		*response_len = 0;
		return NULL;
	}


	*response_len = php_stream_copy_to_mem(stream, &retval, PHP_STREAM_COPY_ALL, 0);
	php_stream_close(stream);
  
	return retval;
}

/**
 * mysqlnd_fabric_handle_digest_auth
 *
 * Takes a php_stream in, and returns a php_stream or NULL
 * If the php_stream has a 200 response, returns unmangled
 * If the php_stream has a 401 response, attempts to do the
 * digest auth, and returns the authed response
 *
 * Otherwise, returns null
 */
php_stream *mysqlnd_fabric_handle_digest_auth(php_stream *stream, char *username, char *password) {
	zval **curhead;
	int response_code;

	char *header_orig, *header_copy;
	char *lasttok, *curtok;
	int toklen;
	int in_quotes = 0;

	zend_function *func_cache = NULL;
	zval hash_in, *ha1, *ha2, *hash_out;
	char *realm, *nonce, *qop, *opaque, *algorithm, *uri;
	int numslashes = 0, urlpos, urllen;
	char cnonce[100];
	int cnoncePos;
	int nonceCount = 1;
	char hash_in_str[256];
	char *response_header, *rh_curpos;
	zval *context_header, **chptr;
	int response_header_len;

	php_stream *authed_stream = NULL;

	if(!stream) { return NULL; }

	// Extract path from URI
	urllen = strlen(stream->orig_path);
	for(urlpos = 0; urlpos < urllen; urlpos++) {
		if(stream->orig_path[urlpos] == '/') {
			numslashes++;
		}
		if(numslashes >= 3) {
			break;
		}
	}
	urllen -= urlpos;
	uri = malloc(urllen + 1);
	strncpy(uri, stream->orig_path + urlpos, urllen+1);

	// Generate cnonce
	// TODO: This should probably be more robust
	cnoncePos = snprintf(cnonce, 100, "%x", rand());
	snprintf(cnonce + cnoncePos, 100 - cnoncePos, "%x", time(NULL));

	zend_hash_internal_pointer_reset(Z_ARRVAL_P(stream->wrapperdata));
	zend_hash_get_current_data(Z_ARRVAL_P(stream->wrapperdata), (void**)&curhead);
	// Response code parsing stolen from http_fopen_wrapper.c in PHP source
	if(Z_STRLEN_PP(curhead) > 9) {
		response_code = atoi(Z_STRVAL_PP(curhead) + 9);
		if(response_code == 200) {
			free(uri);
			return stream;
		} else if(response_code == 401) {
			do {
				zend_hash_move_forward(Z_ARRVAL_P(stream->wrapperdata));
				if(zend_hash_get_current_data(Z_ARRVAL_P(stream->wrapperdata), (void**)&curhead) != SUCCESS) {
					break;
				}
			} while(strncmp(Z_STRVAL_PP(curhead), "WWW-Authenticate: Digest", sizeof("WWW-Authenticate: Digest") - 1) != 0);
			
			in_quotes = 0;
			header_orig = Z_STRVAL_PP(curhead);
			header_copy = malloc(Z_STRLEN_PP(curhead)+1);
			strncpy(header_copy, header_orig, Z_STRLEN_PP(curhead)+1);
			curtok = header_copy;
			lasttok = curtok;
			while(curtok = strtok(curtok, " =,\r\n")) {
				toklen = strlen(curtok);

				if(in_quotes) {
					// Replace the nulled character
					// Pointer math, yay
					curtok[-1] = header_orig[(curtok - 1) - header_copy];

					// Check for an ending quote
					if(curtok[toklen - 1] == '"') {
						curtok[toklen - 1] = '\0';
						in_quotes = 0;
					}
					curtok = NULL;
					continue;
				}

				if(curtok[0] == '"') {
					// Check for ending quote
					if(curtok[toklen - 1] == '"') {
						curtok[toklen - 1] = '\0';
					} else {
						in_quotes = 1;
					}

					// Move past the starting quote
					curtok++;
				}

				if(strncmp(lasttok, "realm", sizeof("realm")) == 0) { realm = curtok; }
				else if(strncmp(lasttok, "nonce", sizeof("nonce")) == 0) { nonce = curtok; }
				else if(strncmp(lasttok, "qop", sizeof("qop")) == 0) { qop = curtok; }
				else if(strncmp(lasttok, "opaque", sizeof("opaque")) == 0) { opaque = curtok; }
				else if(strncmp(lasttok, "algorithm", sizeof("algorithm")) == 0) { algorithm = curtok; }

				lasttok = curtok;
				curtok = NULL;
			}
			
			if(realm && nonce && qop) {
				ALLOC_INIT_ZVAL(ha1);
				ALLOC_INIT_ZVAL(ha2);
				INIT_ZVAL(hash_in);

				snprintf(hash_in_str, 256, "%s:%s:%s", username, realm, password);
				ZVAL_STRINGL(&hash_in, hash_in_str, strlen(hash_in_str), 0);
				zend_call_method_with_1_params(NULL, NULL, &func_cache, "md5", &ha1, &hash_in);

				snprintf(hash_in_str, 256, "%s:%s", "POST", uri);
				ZVAL_STRINGL(&hash_in, hash_in_str, strlen(hash_in_str), 0);
				zend_call_method_with_1_params(NULL, NULL, &func_cache, "md5", &ha2, &hash_in);

				snprintf(hash_in_str, 256, "%s:%s:%08x:%s:%s:%s",
				Z_STRVAL_P(ha1), nonce, nonceCount, cnonce, qop, Z_STRVAL_P(ha2));
				ZVAL_STRINGL(&hash_in, hash_in_str, strlen(hash_in_str), 0);
				zend_call_method_with_1_params(NULL, NULL, &func_cache, "md5", &hash_out, &hash_in);

				// Build the response header
				// Get any previous headers
				php_stream_context_get_option(stream->context, "http", "header", &chptr);
				context_header = *chptr;

				// Allocate original header + 2x response header, should be plenty
				response_header_len = Z_STRLEN_P(context_header) + strlen(header_orig)*2;
				response_header = malloc(response_header_len + 1);
				rh_curpos = response_header;

				strncpy(rh_curpos, Z_STRVAL_P(context_header), Z_STRLEN_P(context_header));
				rh_curpos += Z_STRLEN_P(context_header);
				strncpy(rh_curpos, "\r\n", 2);
				rh_curpos += 2;
				strncpy(rh_curpos, "Authorization: Digest", strlen("Authorization: Digest"));
				rh_curpos += strlen("Authorization: Digest");
				rh_curpos += snprintf(rh_curpos, response_header_len - (rh_curpos - response_header),
					" username=\"%s\","
					" realm=\"%s\","
					" nonce=\"%s\","
					" uri=\"%s\","
					" qop=auth,"
					" nc=%08x,"
					" cnonce=\"%s\","
					" response=\"%s\",",
					username,
					realm,
					nonce,
					uri,
					nonceCount,
					cnonce,
					Z_STRVAL_P(hash_out),
					opaque);
				if(opaque) {
					rh_curpos += snprintf(rh_curpos, response_header_len - (rh_curpos - response_header), " opaque=\"%s\",", opaque);
				}
				if(algorithm) {
					rh_curpos += snprintf(rh_curpos, response_header_len - (rh_curpos - response_header), " algorithm=\"%s\",", algorithm);
				}
				// Overwrite the previous comma
				snprintf(rh_curpos-1, response_header_len - (rh_curpos - response_header), "\r\n");

				ZVAL_STRING(context_header, response_header, 1);
				php_stream_context_set_option(stream->context, "http", "header", context_header);
				authed_stream = php_stream_open_wrapper_ex(stream->orig_path, "rb", REPORT_ERRORS, NULL, stream->context);
				// Close the old stream, memory!
				php_stream_close(stream);

				free(uri);
				free(header_copy);
				free(response_header);
				return authed_stream;
			} else {
				//TODO: Raise an error/notice
				free(uri);
				free(header_copy);
				return NULL;
			}
		}
	}

	free(uri);
	return NULL;
}

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
