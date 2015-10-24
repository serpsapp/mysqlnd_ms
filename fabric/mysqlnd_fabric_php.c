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
#include "main/php.h"
#include "main/spprintf.h"
#include "main/php_streams.h"

#include "mysqlnd_fabric.h"
#include "mysqlnd_fabric_priv.h"

#include "libdigest/digest.h"

char *mysqlnd_fabric_http(mysqlnd_fabric *fabric, char *url, char *request_body, size_t request_body_len, size_t *response_len)
{
    char *retval;
	zval method, content, header, ignore_errors;
	php_stream_context *ctxt;
	php_stream *stream = NULL;

	zval *wrapperdata, **curhead;
	int response_code;
	char *digest;
	char lasttok[10];
	char *realm;


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
			
			lasttok[0] = '\0';
			while(realm = strtok(Z_STRVAL_PP(curhead), " =\"")) {
				if(strncmp(lasttok, "realm", sizeof("realm")) == 0) {
					break;
				} else {
					realm = 0;
				}
			}

			if(realm) {
				digest = compute_digest("admin", realm, "***REMOVED***");
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
