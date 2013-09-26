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

#include "ext/standard/php_rand.h"

#define FABRIC_SHARD_LOOKUP_XML "<?xml version=\"1.0\" encoding=\"iso-8859-1\"?>\n" \
			"<methodCall><methodName>sharding.lookup_servers</methodName><params>\n" \
			"<param><!-- table --><value><string>%s</string></value></param>\n" \
			"<param><!-- shard key --><value><string>%s</string></value></param>\n" \
			"<param><!-- hint --><value><string>%s</string></value></param>\n" \
			"<param><!-- sync --><value><boolean>1</boolean></value></param></params>\n" \
			"</methodCall>"

static void mysqlnd_fabric_host_shuffle(mysqlnd_fabric_host *a, size_t n)
{
	TSRMLS_FETCH();
	
	if (!BG(mt_rand_is_seeded)) {
		php_mt_srand(GENERATE_SEED() TSRMLS_CC);
	}
	
	if (n > 1) {
		size_t i;
		for (i = 0; i < n - 1; i++)  {
			size_t j = i + php_mt_rand(TSRMLS_C) / (PHP_MT_RAND_MAX / (n - i) + 1);
			mysqlnd_fabric_host t = a[j];
			a[j] = a[i];
			a[i] = t;
		}
	}
}

mysqlnd_fabric *mysqlnd_fabric_init()
{
	mysqlnd_fabric *fabric = ecalloc(1, sizeof(mysqlnd_fabric));
	return fabric;
}

void mysqlnd_fabric_free(mysqlnd_fabric *fabric)
{
	int i;
	for (i = 0; i < fabric->host_count ; ++i) {
		efree(fabric->hosts[i].hostname);
	}
	efree(fabric);
}

int mysqlnd_fabric_add_host(mysqlnd_fabric *fabric, char *hostname, int port)
{
	if (fabric->host_count >= 10) {
		return 1;
	}
	
	fabric->hosts[fabric->host_count].hostname = estrdup(hostname);
	fabric->hosts[fabric->host_count].port = port;
	fabric->host_count++;	
	
	return 0;
}

static php_stream *mysqlnd_fabric_open_stream(mysqlnd_fabric *fabric,char *request_body)
{
	zval method, content, header;
	php_stream_context *ctxt;
	php_stream *stream = NULL;
	mysqlnd_fabric_host *server;
	TSRMLS_FETCH();
	
	ZVAL_STRING(&method, "POST", 0);
	ZVAL_STRING(&content, request_body, 0);
	ZVAL_STRING(&header, "Content-type: application/x-www-form-urlencoded", 0);
	
	/* prevent anybody from freeing these */
	Z_SET_ISREF(method);
	Z_SET_ISREF(content);
	Z_SET_ISREF(header);
	Z_SET_REFCOUNT(method, 2);
	Z_SET_REFCOUNT(content, 2);
	Z_SET_REFCOUNT(header, 2);
	
	ctxt = php_stream_context_alloc(TSRMLS_C);
	php_stream_context_set_option(ctxt, "http", "method", &method);
	php_stream_context_set_option(ctxt, "http", "content", &content);
	php_stream_context_set_option(ctxt, "http", "header", &header);

	mysqlnd_fabric_host_shuffle(fabric->hosts, fabric->host_count - 1);
	for (server = fabric->hosts; !stream && server < fabric->hosts  + fabric->host_count; server++) {
		char *url = NULL;
		
		spprintf(&url, 0, "http://%s:%d/", server->hostname, server->port);
	
		/* TODO: Switch to quiet mode */
		stream = php_stream_open_wrapper_ex(url, "rb", REPORT_ERRORS, NULL, ctxt);
		efree(url);
	};
	
	return stream;
}

mysqlnd_fabric_server *mysqlnd_fabric_get_shard_servers(mysqlnd_fabric *fabric, const char *table, const char *key, enum mysqlnd_fabric_hint hint)
{
	int len;
	char *req = NULL;
	char foo[4001];
	php_stream *stream;
	
	if (!fabric->host_count) {
		return NULL;
	}
	
	spprintf(&req, 0, FABRIC_SHARD_LOOKUP_XML, table, key ? key : "", hint == LOCAL ? "LOCAL" : "GLOBAL");

	stream = mysqlnd_fabric_open_stream(fabric, req);
	if (!stream) {
		efree(req);
		return NULL;
	}
	
	len = php_stream_read(stream, foo, 4000);
	foo[len] = '\0';
	/* TODO: what happens with a response > 4000 bytes ... needs to be handled once we have the dump API */

	php_stream_close(stream);
	
	efree(req);
	
	return mysqlnd_fabric_parse_xml(foo, len);
}

void mysqlnd_fabric_free_server_list(mysqlnd_fabric_server *servers)
{
	mysqlnd_fabric_server *pos;
	
	if (!servers) {
		return;
	}
	
	for (pos = servers; pos->hostname; pos++) {
		efree(pos->hostname);
		efree(pos->uuid);
	}
	efree(servers);
}

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
