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

/* $Id: mysqlnd_ms.c 311179 2011-05-18 11:26:22Z andrey $ */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "ext/mysqlnd/mysqlnd.h"
#include "ext/mysqlnd/mysqlnd_debug.h"
#include "ext/mysqlnd/mysqlnd_priv.h"
#ifndef mnd_emalloc
#include "ext/mysqlnd/mysqlnd_alloc.h"
#endif
#include "mysqlnd_ms.h"
#include "ext/standard/php_rand.h"
#include "mysqlnd_ms_switch.h"
#include "mysqlnd_ms_enum_n_def.h"


/* {{{ mysqlnd_ms_choose_connection_random */
MYSQLND *
mysqlnd_ms_choose_connection_random(void * f_data, const char * const query, const size_t query_len,
									struct mysqlnd_ms_lb_strategies * stgy, MYSQLND_ERROR_INFO * error_info,
									zend_llist * master_connections, zend_llist * slave_connections,
									enum enum_which_server * which_server TSRMLS_DC)
{
	MYSQLND_MS_FILTER_RANDOM_DATA * filter = (MYSQLND_MS_FILTER_RANDOM_DATA *) f_data;
	zend_bool forced;
	enum enum_which_server tmp_which;
	smart_str fprint = {0};
	DBG_ENTER("mysqlnd_ms_choose_connection_random");

	if (!which_server) {
		which_server = &tmp_which;
	}
	*which_server = mysqlnd_ms_query_is_select(query, query_len, &forced TSRMLS_CC);
	if ((stgy->trx_stickiness_strategy == TRX_STICKINESS_STRATEGY_MASTER) && stgy->in_transaction && !forced) {
		DBG_INF("Enforcing use of master while in transaction");
		*which_server = USE_MASTER;
		MYSQLND_MS_INC_STATISTIC(MS_STAT_TRX_MASTER_FORCED);
	} else if (stgy->mysqlnd_ms_flag_master_on_write) {
		if (*which_server != USE_MASTER) {
			if (stgy->master_used && !forced) {
				switch (*which_server) {
					case USE_MASTER:
					case USE_LAST_USED:
						break;
					case USE_SLAVE:
					default:
						DBG_INF("Enforcing use of master after write");
						*which_server = USE_MASTER;
						break;
				}
			}
		} else {
			DBG_INF("Use of master detected");
			stgy->master_used = TRUE;
		}
	}

	switch (*which_server) {
		case USE_SLAVE:
		{
			zend_llist_position	pos;
			zend_llist * l = slave_connections;
			MYSQLND_MS_LIST_DATA * element = NULL, ** element_pp = NULL;
			unsigned long rnd_idx;
			uint i = 0;
			MYSQLND * connection = NULL;
			MYSQLND ** context_pos;
			mysqlnd_ms_get_fingerprint(&fprint, l TSRMLS_CC);

			DBG_INF_FMT("%d slaves to choose from", zend_llist_count(l));

			/* LOCK on context ??? */
			switch (zend_hash_find(&filter->sticky.slave_context, fprint.c, fprint.len /*\0 counted*/, (void **) &context_pos)) {
				case SUCCESS:
					smart_str_free(&fprint);
					connection = context_pos? *context_pos : NULL;
					if (!connection) {
						char error_buf[256];
						snprintf(error_buf, sizeof(error_buf), MYSQLND_MS_ERROR_PREFIX " Something is very wrong for slave random/once.");
						error_buf[sizeof(error_buf) - 1] = '\0';
						DBG_ERR(error_buf);
						SET_CLIENT_ERROR((*error_info), CR_UNKNOWN_ERROR, UNKNOWN_SQLSTATE, error_buf);
						php_error_docref(NULL TSRMLS_CC, E_RECOVERABLE_ERROR, "%s", error_buf);
					} else {
						DBG_INF_FMT("Using already selected slave connection "MYSQLND_LLU_SPEC, connection->thread_id);
						MYSQLND_MS_INC_STATISTIC(MS_STAT_USE_SLAVE);
						SET_EMPTY_ERROR(MYSQLND_MS_ERROR_INFO(connection));
						DBG_RETURN(connection);
					}
					break;
				case FAILURE:
					rnd_idx = php_rand(TSRMLS_C);
					RAND_RANGE(rnd_idx, 0, zend_llist_count(l) - 1, PHP_RAND_MAX);
					DBG_INF_FMT("USE_SLAVE rnd_idx=%lu", rnd_idx);

					element_pp = (MYSQLND_MS_LIST_DATA **) zend_llist_get_first_ex(l, &pos);
					while (i++ < rnd_idx) {
						element_pp = (MYSQLND_MS_LIST_DATA **) zend_llist_get_next_ex(l, &pos);
					}
					connection = (element_pp && (element = *element_pp) && element->conn) ? element->conn : NULL;

					if (!connection) {
						smart_str_free(&fprint);
						if (SERVER_FAILOVER_DISABLED == stgy->failover_strategy) {
							/* TODO: connection error would be better */
							char error_buf[256];
							snprintf(error_buf, sizeof(error_buf), MYSQLND_MS_ERROR_PREFIX " Couldn't find the appropriate slave connection. %d slaves to choose from. Something is wrong", zend_llist_count(l));
							error_buf[sizeof(error_buf) - 1] = '\0';
							SET_CLIENT_ERROR((*error_info), CR_UNKNOWN_ERROR, UNKNOWN_SQLSTATE, error_buf);
							php_error_docref(NULL TSRMLS_CC, E_WARNING, "%s", error_buf);
							/* should be a very rare case to be here - connection shouldn't be NULL in first place */
							DBG_RETURN(NULL);
						}
					} else {
						if (CONN_GET_STATE(connection) > CONN_ALLOCED || PASS == mysqlnd_ms_lazy_connect(element, FALSE TSRMLS_CC)) {
							MYSQLND_MS_INC_STATISTIC(MS_STAT_USE_SLAVE);
							SET_EMPTY_ERROR(MYSQLND_MS_ERROR_INFO(connection));
							if (TRUE == filter->sticky.once) {
								zend_hash_update(&filter->sticky.slave_context, fprint.c, fprint.len /*\0 counted*/, &connection,
												 sizeof(MYSQLND *), NULL);
							}
							smart_str_free(&fprint);
							DBG_RETURN(connection);
						}
						smart_str_free(&fprint);
						if (SERVER_FAILOVER_DISABLED == stgy->failover_strategy) {
							/* no failover */
							DBG_INF("Failover disabled");
							DBG_RETURN(connection);
						}
						/* falling-through */
					}
			}/* switch (zend_hash_find) */
		}
		DBG_INF("FAIL-OVER");
		/* fall-through */
		case USE_MASTER:
		{
			zend_llist_position	pos;
			zend_llist * l = master_connections;
			MYSQLND_MS_LIST_DATA * element = NULL, ** element_pp = NULL;
			unsigned long rnd_idx;
			uint i = 0;
			MYSQLND * connection = NULL;
			MYSQLND ** context_pos;
			mysqlnd_ms_get_fingerprint(&fprint, l TSRMLS_CC);

			DBG_INF_FMT("%d masters to choose from", zend_llist_count(l));

			/* LOCK on context ??? */
			switch (zend_hash_find(&filter->sticky.master_context, fprint.c, fprint.len /*\0 counted*/, (void **) &context_pos)) {
				case SUCCESS:
					connection = context_pos? *context_pos : NULL;
					smart_str_free(&fprint);
					if (!connection) {
						char error_buf[256];
						snprintf(error_buf, sizeof(error_buf), MYSQLND_MS_ERROR_PREFIX " Something is very wrong for master random/once.");
						error_buf[sizeof(error_buf) - 1] = '\0';
						DBG_ERR(error_buf);
						SET_CLIENT_ERROR((*error_info), CR_UNKNOWN_ERROR, UNKNOWN_SQLSTATE, error_buf);
						php_error_docref(NULL TSRMLS_CC, E_RECOVERABLE_ERROR, "%s", error_buf);
						DBG_RETURN(NULL);
					} else {
						DBG_INF_FMT("Using already selected master connection "MYSQLND_LLU_SPEC, connection->thread_id);
						MYSQLND_MS_INC_STATISTIC(MS_STAT_USE_MASTER);
						SET_EMPTY_ERROR(MYSQLND_MS_ERROR_INFO(connection));
						DBG_RETURN(connection);
					}
					break;
				case FAILURE:
					rnd_idx = php_rand(TSRMLS_C);
					RAND_RANGE(rnd_idx, 0, zend_llist_count(l) - 1, PHP_RAND_MAX);
					DBG_INF_FMT("USE_MASTER rnd_idx=%lu", rnd_idx);

					element_pp = (MYSQLND_MS_LIST_DATA **) zend_llist_get_first_ex(l, &pos);
					while (i++ < rnd_idx) {
						element_pp = (MYSQLND_MS_LIST_DATA **) zend_llist_get_next_ex(l, &pos);
					}
					connection = (element_pp && (element = *element_pp) && element->conn) ? element->conn : NULL;

					if (connection) {
						if (CONN_GET_STATE(connection) > CONN_ALLOCED || PASS == mysqlnd_ms_lazy_connect(element, TRUE TSRMLS_CC)) {
							MYSQLND_MS_INC_STATISTIC(MS_STAT_USE_MASTER);
							SET_EMPTY_ERROR(MYSQLND_MS_ERROR_INFO(connection));
							if (TRUE == filter->sticky.once) {
								zend_hash_update(&filter->sticky.master_context, fprint.c, fprint.len /*\0 counted*/, &connection,
												 sizeof(MYSQLND *), NULL);
							}
						}
					} else {
						char error_buf[256];
						snprintf(error_buf, sizeof(error_buf), MYSQLND_MS_ERROR_PREFIX " Couldn't find the appropriate master connection. %d masters to choose from. Something is wrong", zend_llist_count(l));
						error_buf[sizeof(error_buf) - 1] = '\0';
						SET_CLIENT_ERROR((*error_info), CR_UNKNOWN_ERROR, UNKNOWN_SQLSTATE, error_buf);
						php_error_docref(NULL TSRMLS_CC, E_WARNING, "%s", error_buf);
					}
					smart_str_free(&fprint);
					DBG_RETURN(connection);
					break;
			}/* switch (zend_hash_find) */
			break;
		}
		case USE_LAST_USED:
			DBG_INF("Using last used connection");
			if (!stgy->last_used_conn) {
				char error_buf[256];
				snprintf(error_buf, sizeof(error_buf), MYSQLND_MS_ERROR_PREFIX " Last used SQL hint cannot be used because last used connection has not been set yet. Statement will fail");
				error_buf[sizeof(error_buf) - 1] = '\0';
				DBG_ERR(error_buf);
				SET_CLIENT_ERROR((*error_info), CR_UNKNOWN_ERROR, UNKNOWN_SQLSTATE, error_buf);
				php_error_docref(NULL TSRMLS_CC, E_WARNING, "%s", error_buf);
			} else {
				SET_EMPTY_ERROR(MYSQLND_MS_ERROR_INFO(stgy->last_used_conn));
			}
			DBG_RETURN(stgy->last_used_conn);
		default:
			/* error */
			break;
	}

	DBG_RETURN(NULL);
}
/* }}} */

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
