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
#ifndef MYSQLND_MS_CONFIG_JSON_H
#define MYSQLND_MS_CONFIG_JSON_H

struct st_mysqlnd_ms_json_config;
struct st_mysqlnd_ms_config_json_entry;

PHPAPI struct st_mysqlnd_ms_json_config * mysqlnd_ms_config_json_init(TSRMLS_D);
PHPAPI void mysqlnd_ms_config_json_free(struct st_mysqlnd_ms_json_config * cfg TSRMLS_DC);
PHPAPI enum_func_status mysqlnd_ms_config_json_load_configuration(struct st_mysqlnd_ms_json_config * cfg TSRMLS_DC);
PHPAPI zend_bool mysqlnd_ms_config_json_section_exists(struct st_mysqlnd_ms_json_config * cfg, const char * section, size_t section_len, zend_bool use_lock TSRMLS_DC);
PHPAPI char * mysqlnd_ms_config_json_string(struct st_mysqlnd_ms_json_config * cfg, const char * section, size_t section_len, const char * name, size_t name_len, zend_bool * exists, zend_bool * is_list_value, zend_bool use_lock TSRMLS_DC);
PHPAPI int64_t mysqlnd_ms_config_json_int(struct st_mysqlnd_ms_json_config * cfg, const char * section, size_t section_len, const char * name, size_t name_len, zend_bool * exists, zend_bool * is_list_value, zend_bool use_lock TSRMLS_DC);
PHPAPI double mysqlnd_ms_config_json_double(struct st_mysqlnd_ms_json_config * cfg, const char * section, size_t section_len, const char * name, size_t name_len, zend_bool * exists, zend_bool * is_list_value, zend_bool use_lock TSRMLS_DC);

PHPAPI void mysqlnd_ms_config_json_reset_section(struct st_mysqlnd_ms_json_config * cfg, const char * section, size_t section_len, zend_bool use_lock TSRMLS_DC);

PHPAPI struct st_mysqlnd_ms_config_json_entry * mysqlnd_ms_config_json_section(struct st_mysqlnd_ms_json_config * cfg, const char * section, size_t section_len, zend_bool * exists TSRMLS_DC);



#ifdef ZTS
PHPAPI void mysqlnd_ms_config_json_lock(struct st_mysqlnd_ms_json_config * cfg, const char * const file, unsigned int line TSRMLS_DC);
PHPAPI void mysqlnd_ms_config_json_unlock(struct st_mysqlnd_ms_json_config * cfg, const char * const file, unsigned int line TSRMLS_DC);
#define MYSQLND_MS_CONFIG_JSON_LOCK(cfg) mysqlnd_ms_config_json_lock((cfg), __FILE__, __LINE__ TSRMLS_CC)
#define MYSQLND_MS_CONFIG_JSON_UNLOCK(cfg) mysqlnd_ms_config_json_unlock((cfg), __FILE__, __LINE__ TSRMLS_CC)
#else
#define MYSQLND_MS_CONFIG_JSON_LOCK(cfg)
#define MYSQLND_MS_CONFIG_JSON_UNLOCK(cfg)
#endif


#endif	/* MYSQLND_MS_CONFIG_JSON_H */


/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
