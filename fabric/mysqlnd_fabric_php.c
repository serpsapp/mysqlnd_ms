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

char *mysqlnd_fabric_http(mysqlnd_fabric *fabric, char *url, char *request_body, size_t request_body_len, size_t *response_len)
{
	char *retval;
	zval method, content, header, ignore_errors;
	php_stream_context *ctxt;
	php_stream *stream = NULL;

	zval *wrapperdata, **curhead;
	int response_code;
	char *digest;
	char *lasttok, *curtok;
	int toklen;
	int in_quotes = 0;
	zend_function *func_cache = NULL;
	zval todigest, *ha1, *ha2, *digest_response;
	char *digest_orig, *digest_copy;
	char *realm, *nonce, *qop;
	char cnonce[] = "[random nonce here]";
	char todigest_str[256];

	TSRMLS_FETCH();
	
	ZVAL_STRINGL(&method, "POST", sizeof("POST")-1, 0);
	ZVAL_STRINGL(&content, request_body, request_body_len, 0);
	ZVAL_STRINGL(&header, "Content-type: text/xml", sizeof("Content-type: text/xml")-1, 0);
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

	/* TODO: Switch to quiet mode? */
	stream = php_stream_open_wrapper_ex(url, "rb", REPORT_ERRORS, NULL, ctxt);
	if (!stream) {
		*response_len = 0;
		return NULL;
	}

	zend_hash_internal_pointer_reset(Z_ARRVAL_P(stream->wrapperdata));
	zend_hash_get_current_data(Z_ARRVAL_P(stream->wrapperdata), (void**)&curhead);
	// Stolen from http_fopen_wrapper.c in PHP source
	if(Z_STRLEN_PP(curhead) > 9) {
		response_code = atoi(Z_STRVAL_PP(curhead) + 9);
		if(response_code == 401) {
			do {
				zend_hash_move_forward(Z_ARRVAL_P(stream->wrapperdata));
				if(zend_hash_get_current_data(Z_ARRVAL_P(stream->wrapperdata), (void**)&curhead) != SUCCESS) {
					break;
				}
			} while(strncmp(Z_STRVAL_PP(curhead), "WWW-Authenticate: Digest", sizeof("WWW-Authenticate: Digest") - 1) != 0);
			
			//TODO: Extract this properly, this doesn't work
			//Also, need to copy so we don't modify curhead
			in_quotes = 0;
			digest_orig = Z_STRVAL_PP(curhead);
			digest_copy = malloc(Z_STRLEN_PP(curhead)+1);
			strncpy(digest_copy, digest_orig, Z_STRLEN_PP(curhead));
			curtok = digest_copy;
			lasttok = curtok;
			while(curtok = strtok(curtok, " =,")) {
				toklen = strlen(curtok);

				if(in_quotes) {
					// Replace the nulled character
					// Pointer math, yay
					curtok[-1] = digest_orig[(curtok - 1) - digest_copy];

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

				lasttok = curtok;
				curtok = NULL;
			}

			if(realm && nonce && qop) {
				ALLOC_INIT_ZVAL(ha1);
				ALLOC_INIT_ZVAL(ha2);
				INIT_ZVAL(todigest);

				//TODO: Make these parameterized
				snprintf(todigest_str, 256, "%s:%s:%s", "admin", realm, "***REMOVED***");
				ZVAL_STRINGL(&todigest, todigest_str, strlen(todigest_str), 0);
				zend_call_method_with_1_params(NULL, NULL, &func_cache, "md5", &ha1, &todigest);
				printf("%s", Z_STRVAL_P(ha1));

				snprintf(todigest_str, 256, "%s:%s", "POST", url);
				ZVAL_STRINGL(&todigest, todigest_str, strlen(todigest_str), 0);
				zend_call_method_with_1_params(NULL, NULL, &func_cache, "md5", &ha2, &todigest);
				printf("%s", Z_STRVAL_P(ha2));

				snprintf(todigest_str, 256, "%s:%s:%s:%s:%s:%s",
					Z_STRVAL_P(ha1), nonce, "1", cnonce, qop, Z_STRVAL_P(ha2));
				ZVAL_STRINGL(&todigest, todigest_str, strlen(todigest_str), 0);
				zend_call_method_with_1_params(NULL, NULL, &func_cache, "md5", &digest_response, &todigest);
				printf("%s", Z_STRVAL_P(digest_response));
			}
		}
	}
	
	*response_len = php_stream_copy_to_mem(stream, &retval, PHP_STREAM_COPY_ALL, 0);
	php_stream_close(stream);
  
	return retval;
}

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
