/*
  +----------------------------------------------------------------------+
  | PHP Version 5                                                        |
  +----------------------------------------------------------------------+
  | Copyright (c) 1997-2008 The PHP Group                                |
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

/* $Id$ */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "ext/standard/info.h"
#include "ext/mysqlnd/mysqlnd.h"
#include "ext/mysqlnd/mysqlnd_debug.h"
#include "ext/mysqlnd/mysqlnd_priv.h"
#if PHP_VERSION_ID >= 50400
#include "ext/mysqlnd/mysqlnd_ext_plugin.h"
#endif
#include "mysqlnd_ms.h"
#include "mysqlnd_ms_config_json.h"
#include "ext/standard/php_rand.h"
#include "mysqlnd_ms_switch.h"

#define STR_W_LEN(str)  str, (sizeof(str) - 1)
const MYSQLND_STRING mysqlnd_ms_stats_values_names[MS_STAT_LAST] =
{
	{ STR_W_LEN("use_slave") },
	{ STR_W_LEN("use_master") },
	{ STR_W_LEN("use_slave_guess") },
	{ STR_W_LEN("use_master_guess") },
	{ STR_W_LEN("use_slave_sql_hint") },
	{ STR_W_LEN("use_master_sql_hint") },
	{ STR_W_LEN("use_last_used_sql_hint") },
	{ STR_W_LEN("use_slave_callback") },
	{ STR_W_LEN("use_master_callback") },
	{ STR_W_LEN("non_lazy_connections_slave_success") },
	{ STR_W_LEN("non_lazy_connections_slave_failure") },
	{ STR_W_LEN("non_lazy_connections_master_success") },
	{ STR_W_LEN("non_lazy_connections_master_failure") },
	{ STR_W_LEN("lazy_connections_slave_success") },
	{ STR_W_LEN("lazy_connections_slave_failure") },
	{ STR_W_LEN("lazy_connections_master_success") },
	{ STR_W_LEN("lazy_connections_master_failure") },
	{ STR_W_LEN("trx_autocommit_on") },
	{ STR_W_LEN("trx_autocommit_off") },
	{ STR_W_LEN("trx_master_forced") }
};
/* }}} */


ZEND_DECLARE_MODULE_GLOBALS(mysqlnd_ms)

unsigned int mysqlnd_ms_plugin_id;

static zend_bool mysqlns_ms_global_config_loaded = FALSE;
struct st_mysqlnd_ms_json_config * mysqlnd_ms_json_config = NULL;


/* {{{ php_mysqlnd_ms_config_init_globals */
static void
php_mysqlnd_ms_config_init_globals(zend_mysqlnd_ms_globals * mysqlnd_ms_globals)
{
	mysqlnd_ms_globals->enable = FALSE;
	mysqlnd_ms_globals->force_config_usage = FALSE;
	mysqlnd_ms_globals->ini_file = NULL;
	mysqlnd_ms_globals->user_pick_server = NULL;
	mysqlnd_ms_globals->collect_statistics = FALSE;
	mysqlnd_ms_globals->multi_master = FALSE;
	mysqlnd_ms_globals->disable_rw_split = FALSE;
}
/* }}} */


/* {{{ PHP_GINIT_FUNCTION */
static PHP_GINIT_FUNCTION(mysqlnd_ms)
{
	php_mysqlnd_ms_config_init_globals(mysqlnd_ms_globals);
}
/* }}} */


/* {{{ PHP_RINIT_FUNCTION */
PHP_RINIT_FUNCTION(mysqlnd_ms)
{
	if (MYSQLND_MS_G(enable)) {
		MYSQLND_MS_CONFIG_JSON_LOCK(mysqlnd_ms_json_config);
		if (FALSE == mysqlns_ms_global_config_loaded) {
			mysqlnd_ms_config_json_load_configuration(mysqlnd_ms_json_config TSRMLS_CC);
			mysqlns_ms_global_config_loaded = TRUE;
		}
		MYSQLND_MS_CONFIG_JSON_UNLOCK(mysqlnd_ms_json_config);
	}
	return SUCCESS;
}
/* }}} */


/* {{{ PHP_RSHUTDOWN_FUNCTION */
PHP_RSHUTDOWN_FUNCTION(mysqlnd_ms)
{
	if (MYSQLND_MS_G(user_pick_server)) {
		zval_ptr_dtor(&MYSQLND_MS_G(user_pick_server));
		MYSQLND_MS_G(user_pick_server) = NULL;
	}
	return SUCCESS;
}
/* }}} */


/* {{{ PHP_INI
 */
PHP_INI_BEGIN()
	STD_PHP_INI_BOOLEAN("mysqlnd_ms.enable", "0", PHP_INI_SYSTEM, OnUpdateBool, enable, zend_mysqlnd_ms_globals, mysqlnd_ms_globals)
	STD_PHP_INI_ENTRY("mysqlnd_ms.force_config_usage", "0", PHP_INI_SYSTEM, OnUpdateBool, force_config_usage, zend_mysqlnd_ms_globals, mysqlnd_ms_globals)
	STD_PHP_INI_ENTRY("mysqlnd_ms.ini_file", NULL, PHP_INI_SYSTEM, OnUpdateString, ini_file, zend_mysqlnd_ms_globals, mysqlnd_ms_globals)
	STD_PHP_INI_ENTRY("mysqlnd_ms.collect_statistics", "0", PHP_INI_SYSTEM, OnUpdateBool, collect_statistics, zend_mysqlnd_ms_globals, mysqlnd_ms_globals)
	STD_PHP_INI_ENTRY("mysqlnd_ms.multi_master", "0", PHP_INI_SYSTEM, OnUpdateBool, multi_master, zend_mysqlnd_ms_globals, mysqlnd_ms_globals)
	STD_PHP_INI_ENTRY("mysqlnd_ms.disable_rw_split", "0", PHP_INI_SYSTEM, OnUpdateBool, disable_rw_split, zend_mysqlnd_ms_globals, mysqlnd_ms_globals)
PHP_INI_END()
/* }}} */


/* {{{ PHP_MINIT_FUNCTION */
PHP_MINIT_FUNCTION(mysqlnd_ms)
{
	ZEND_INIT_MODULE_GLOBALS(mysqlnd_ms, php_mysqlnd_ms_config_init_globals, NULL);
	REGISTER_INI_ENTRIES();

	if (MYSQLND_MS_G(enable)) {
		mysqlnd_ms_plugin_id = mysqlnd_plugin_register();
		mysqlnd_ms_register_hooks();
		mysqlnd_stats_init(&mysqlnd_ms_stats, MS_STAT_LAST);

		mysqlnd_ms_json_config = mysqlnd_ms_config_json_init(TSRMLS_C);
	}

	REGISTER_STRING_CONSTANT("MYSQLND_MS_VERSION", MYSQLND_MS_VERSION, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("MYSQLND_MS_VERSION_ID", MYSQLND_MS_VERSION_ID, CONST_CS | CONST_PERSISTENT);

	REGISTER_STRING_CONSTANT("MYSQLND_MS_MASTER_SWITCH", MASTER_SWITCH, CONST_CS | CONST_PERSISTENT);
	REGISTER_STRING_CONSTANT("MYSQLND_MS_SLAVE_SWITCH", SLAVE_SWITCH, CONST_CS | CONST_PERSISTENT);
	REGISTER_STRING_CONSTANT("MYSQLND_MS_LAST_USED_SWITCH", LAST_USED_SWITCH, CONST_CS | CONST_PERSISTENT);
#ifdef ALL_SERVER_DISPATCH
	REGISTER_STRING_CONSTANT("MYSQLND_MS_ALL_SERVER_SWITCH", ALL_SERVER_SWITCH, CONST_CS | CONST_PERSISTENT);
#endif
	REGISTER_LONG_CONSTANT("MYSQLND_MS_QUERY_USE_MASTER", USE_MASTER, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("MYSQLND_MS_QUERY_USE_SLAVE", USE_SLAVE, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("MYSQLND_MS_QUERY_USE_LAST_USED", USE_LAST_USED, CONST_CS | CONST_PERSISTENT);

#ifdef MYSQLND_MS_HAVE_FILTER_TABLE_PARTITION
	REGISTER_LONG_CONSTANT("MYSQLND_MS_HAVE_FILTER_TABLE_PARTITION", 1, CONST_CS | CONST_PERSISTENT);
#endif

	return SUCCESS;
}
/* }}} */

/* {{{ PHP_MSHUTDOWN_FUNCTION
 */
PHP_MSHUTDOWN_FUNCTION(mysqlnd_ms)
{
	UNREGISTER_INI_ENTRIES();
	if (MYSQLND_MS_G(enable)) {
		mysqlnd_ms_config_json_free(mysqlnd_ms_json_config TSRMLS_CC);
		mysqlnd_ms_json_config = NULL;
	}
	return SUCCESS;
}
/* }}} */


/* {{{ PHP_MINFO_FUNCTION
 */
PHP_MINFO_FUNCTION(mysqlnd_ms)
{
	char buf[64];

	php_info_print_table_start();
	php_info_print_table_header(2, "mysqlnd_ms support", "enabled");
	snprintf(buf, sizeof(buf), "%s (%d)", MYSQLND_MS_VERSION, MYSQLND_MS_VERSION_ID);
	php_info_print_table_row(2, "Mysqlnd master/slave plugin version", buf);
	php_info_print_table_row(2, "Plugin active", MYSQLND_MS_G(enable) ? "yes" : "no");
#if PHP_VERSION_ID >= 50399
	php_info_print_table_row(2, "Transaction mode trx_stickiness supported", "yes");
#else
	php_info_print_table_row(2, "Transaction mode trx_stickiness supported", "no");
#endif
	php_info_print_table_row(2, "Table partitioning filter supported",
#ifdef MYSQLND_MS_HAVE_FILTER_TABLE_PARTITION
		"yes"
#else
		"no"
#endif
	);
	php_info_print_table_end();

	DISPLAY_INI_ENTRIES();
}
/* }}} */

ZEND_BEGIN_ARG_INFO_EX(arginfo_mysqlnd_ms_set_user_pick_server, 0, 0, 1)
	ZEND_ARG_INFO(0, pick_server_cb)
ZEND_END_ARG_INFO()


#ifdef REINTRODUCE_LATER
/* {{{ mysqlnd_ms_set_user_pick_server */
static void
mysqlnd_ms_set_user_pick_server_aux(INTERNAL_FUNCTION_PARAMETERS)
{
	zval * arg = NULL;
	char * name;

	DBG_ENTER("mysqlnd_ms_set_user_pick_server_aux");

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z", &arg) == FAILURE) {
		DBG_VOID_RETURN;
	}

	if (!zend_is_callable(arg, 0, &name TSRMLS_CC)) {
		php_error_docref(NULL TSRMLS_CC, E_RECOVERABLE_ERROR, "Argument is not a valid callback");
		efree(name);
		RETVAL_FALSE;
		DBG_VOID_RETURN;
	}
	DBG_INF_FMT("name=%s", name);
	efree(name);

	if (MYSQLND_MS_G(user_pick_server) != NULL) {
		zval_ptr_dtor(&MYSQLND_MS_G(user_pick_server));
	}
	MYSQLND_MS_G(user_pick_server) = arg;
	Z_ADDREF_P(arg);

	RETVAL_TRUE;
	DBG_VOID_RETURN;
}
/* }}} */


/* {{{ proto bool mysqlnd_ms_set_user_pick_server(string is_select)
   Sets use_pick function callback */
static PHP_FUNCTION(mysqlnd_ms_set_user_pick_server)
{
	mysqlnd_ms_set_user_pick_server_aux(INTERNAL_FUNCTION_PARAM_PASSTHRU);
}
/* }}} */
#endif

ZEND_BEGIN_ARG_INFO_EX(arginfo_mysqlnd_ms_match_wild, 0, 0, 2)
  ZEND_ARG_INFO(0, haystack)
  ZEND_ARG_INFO(0, wild)
ZEND_END_ARG_INFO()

/* {{{ proto long mysqlnd_ms_match_wild(string haystack, string wild)
   */
static PHP_FUNCTION(mysqlnd_ms_match_wild)
{
	char * str;
	char * wild;
	int tmp;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss", &str, &tmp, &wild, &tmp) == FAILURE) {
		return;
	}

	RETURN_BOOL(mysqlnd_ms_match_wild(str, wild TSRMLS_CC));
}
/* }}} */

#if PHP_VERSION_ID > 50399
ZEND_BEGIN_ARG_INFO_EX(arginfo_mysqlnd_ms_get_last_used_connection, 0, 0, 1)
	ZEND_ARG_INFO(0, object)
ZEND_END_ARG_INFO()


/* {{{ proto array mysqlnd_ms_get_last_used_connection(object handle)
   */
static PHP_FUNCTION(mysqlnd_ms_get_last_used_connection)
{
	zval * handle;
	MYSQLND * proxy_conn;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z", &handle) == FAILURE) {
		return;
	}
	if (!(proxy_conn = zval_to_mysqlnd(handle TSRMLS_CC))) {
		RETURN_FALSE;
	}
	{
		MYSQLND_MS_CONN_DATA ** conn_data = (MYSQLND_MS_CONN_DATA **) mysqlnd_plugin_get_plugin_connection_data(proxy_conn, mysqlnd_ms_plugin_id);
		const MYSQLND * conn = (conn_data && (*conn_data) && (*conn_data)->stgy.last_used_conn)? (*conn_data)->stgy.last_used_conn:proxy_conn;

		array_init(return_value);
		add_assoc_string_ex(return_value, "scheme", sizeof("scheme"), conn->scheme? conn->scheme:"", 1);
		add_assoc_string_ex(return_value, "host", sizeof("host"), conn->host? conn->host:"", 1);
		add_assoc_long_ex(return_value, "port", sizeof("port"), conn->port);
		add_assoc_long_ex(return_value, "thread_id", sizeof("thread_id"), conn->thread_id);
		add_assoc_string_ex(return_value, "last_message", sizeof("last_message"), conn->last_message? conn->last_message:"", 1);
		add_assoc_long_ex(return_value, "errno", sizeof("errno"), conn->error_info.error_no);
		add_assoc_string_ex(return_value, "error", sizeof("error"), (char *) conn->error_info.error, 1);
		add_assoc_string_ex(return_value, "sqlstate", sizeof("sqlstate"), (char *) conn->error_info.sqlstate, 1);
	}
}
/* }}} */
#endif

ZEND_BEGIN_ARG_INFO_EX(arginfo_mysqlnd_ms_query_is_select, 0, 0, 1)
	ZEND_ARG_INFO(0, query)
ZEND_END_ARG_INFO()


/* {{{ proto long mysqlnd_ms_query_is_select(string query)
   Parse query and propose where to send it */
static PHP_FUNCTION(mysqlnd_ms_query_is_select)
{
	char * query;
	int query_len;
	zend_bool forced;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &query, &query_len) == FAILURE) {
		return;
	}

	RETURN_LONG(mysqlnd_ms_query_is_select(query, query_len, &forced TSRMLS_CC));
}
/* }}} */


ZEND_BEGIN_ARG_INFO_EX(arginfo_mysqlnd_ms_get_stats, 0, 0, 0)
ZEND_END_ARG_INFO()


/* {{{ proto array mysqlnd_ms_get_stats()
    Return statistics on connections and queries */
static PHP_FUNCTION(mysqlnd_ms_get_stats)
{
	DBG_ENTER("mysqlnd_ms_get_stats");
	if (zend_parse_parameters_none() == FAILURE) {
		DBG_VOID_RETURN;
	}

	if (!MYSQLND_MS_G(enable)) {
		DBG_VOID_RETURN;
	}

	mysqlnd_fill_stats_hash(mysqlnd_ms_stats, mysqlnd_ms_stats_values_names, return_value TSRMLS_CC ZEND_FILE_LINE_CC);

	DBG_VOID_RETURN;
}
/* }}} */


/* {{{ mysqlnd_ms_deps[] */
static const zend_module_dep mysqlnd_ms_deps[] = {
	ZEND_MOD_REQUIRED("mysqlnd")
	ZEND_MOD_REQUIRED("standard")
	ZEND_MOD_REQUIRED("json")
	{NULL, NULL, NULL}
};
/* }}} */


/* {{{ mysqlnd_ms_functions */
static const zend_function_entry mysqlnd_ms_functions[] = {
#ifdef REINTRODUCE_LATER
	PHP_FE(mysqlnd_ms_set_user_pick_server,	arginfo_mysqlnd_ms_set_user_pick_server)
#endif
	PHP_FE(mysqlnd_ms_match_wild,	arginfo_mysqlnd_ms_match_wild)
	PHP_FE(mysqlnd_ms_query_is_select,	arginfo_mysqlnd_ms_query_is_select)
	PHP_FE(mysqlnd_ms_get_stats,	arginfo_mysqlnd_ms_get_stats)
#if PHP_VERSION_ID > 50399
	PHP_FE(mysqlnd_ms_get_last_used_connection,	arginfo_mysqlnd_ms_get_stats)
#endif
	{NULL, NULL, NULL}	/* Must be the last line in mysqlnd_ms_functions[] */
};
/* }}} */


/* {{{ mysqlnd_ms_module_entry */
zend_module_entry mysqlnd_ms_module_entry = {
	STANDARD_MODULE_HEADER_EX,
	NULL,
	mysqlnd_ms_deps,
	"mysqlnd_ms",
	mysqlnd_ms_functions,
	PHP_MINIT(mysqlnd_ms),
	PHP_MSHUTDOWN(mysqlnd_ms),
	PHP_RINIT(mysqlnd_ms),
	PHP_RSHUTDOWN(mysqlnd_ms),
	PHP_MINFO(mysqlnd_ms),
	MYSQLND_MS_VERSION,
	PHP_MODULE_GLOBALS(mysqlnd_ms),
	PHP_GINIT(mysqlnd_ms),
	NULL,
	NULL,
	STANDARD_MODULE_PROPERTIES_EX
};
/* }}} */

#ifdef COMPILE_DL_MYSQLND_MS
ZEND_GET_MODULE(mysqlnd_ms)
#endif


/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
