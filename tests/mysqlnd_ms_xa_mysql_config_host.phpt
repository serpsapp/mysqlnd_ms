--TEST--
XA state store mysql: host config
--SKIPIF--
<?php
require_once('skipif.inc');
require_once("connect.inc");
require_once("util.inc");

if (($emulated_master_host == $emulated_slave_host)) {
	die("SKIP Emulated master and emulated slave seem to the the same, see tests/README");
}

_skipif_check_extensions(array("mysqli"));
_skipif_connect($emulated_master_host_only, $user, $passwd, $db, $emulated_master_port, $emulated_master_socket);
_skipif_connect($emulated_slave_host_only, $user, $passwd, $db, $emulated_slave_port, $emulated_slave_socket);

_skipif_can_connect("pleaseletmebeinvalid", $user, $passwd, $db, $emulated_master_port, $emulated_master_socket, "Testing invalid host");

if (($error = mst_mysqli_setup_xa_tables($emulated_master_host_only, $user, $passwd, $db, $emulated_master_port, $emulated_master_socket)) ||
	($error = mst_mysqli_flush_xa_tables($emulated_master_host_only, $user, $passwd, $db, $emulated_master_port, $emulated_master_socket))) {
	die(sprintf("SKIP %s\n", $error));
}

$settings = array(
	"host_error" => array(
		'master' => array($emulated_master_host),
		'slave' => array($emulated_slave_host),
		'xa' => array(
			'state_store' => array(
				'participant_localhost_ip' => '127.0.0.1',
				'mysql' =>
				array(
					'host' => 'pleaseletmebeinvalid',
					'user' => $user,
					'password' => $passwd,
					'db'   => $db,
					'port' => $emulated_master_port,
					'socket' => $emulated_master_socket,
			))),
	),
	"host_type" => array(
		'master' => array($emulated_master_host),
		'slave' => array($emulated_slave_host),
		'xa' => array(
			'state_store' => array(
				'participant_localhost_ip' => '127.0.0.1',
				'mysql' =>
				array(
					'host' => array($emulated_master_host_only),
					'user' => $user,
					'password' => $passwd,
					'db'   => $db,
					'port' => $emulated_master_port,
					'socket' => $emulated_master_socket,
			))),
	),
);
if ($error = mst_create_config("test_mysqlnd_ms_xa_mysql_config_host.ini", $settings))
	die(sprintf("SKIP %s\n", $error));
?>
--INI--
mysqlnd_ms.enable=1
mysqlnd_ms.config_file=test_mysqlnd_ms_xa_mysql_config_host.ini
--FILE--
<?php
	require_once("connect.inc");
	require_once("util.inc");

	set_error_handler('mst_error_handler');

	if (!($link = mst_mysqli_connect("host_type", $user, $passwd, $db, $port, $socket)))
		printf("[001] [%d] %s\n", mysqli_connect_errno(), mysqli_connect_error());

	$xa_id = mt_rand(0, 1000);
	var_dump(mysqlnd_ms_xa_begin($link, $xa_id));
	if ($error = mst_mysqli_flush_xa_tables($emulated_master_host_only, $user, $passwd, $db, $emulated_master_port, $emulated_master_socket)) {
		printf("[002] %s\n", $error);
	}

	if (!($link = mst_mysqli_connect("host_error", $user, $passwd, $db, $port, $socket)))
		printf("[003] [%d] %s\n", mysqli_connect_errno(), mysqli_connect_error());

	var_dump(mysqlnd_ms_xa_begin($link, $xa_id));

	print "done!";
?>
--CLEAN--
<?php
	require_once("connect.inc");
	require_once("util.inc");

	if (!unlink("test_mysqlnd_ms_xa_mysql_config_host.ini")) {
		printf("[clean] Cannot unlink ini file 'test_mysqlnd_ms_xa_mysql_config_host.ini'.\n");
	}

	if (($error = mst_mysqli_drop_xa_tables($emulated_master_host_only, $user, $passwd, $db, $emulated_master_port, $emulated_master_socket))) {
		printf("[clean] %s\n", $error);
	}
?>
--EXPECTF--
[E_RECOVERABLE_ERROR] mysqli_real_connect(): (mysqlnd_ms) 'host' from 'xa' must be a string in %s on line %d
[E_WARNING] mysqlnd_ms_xa_begin(): (mysqlnd_ms) MySQL XA state store error: %s in %s on line %d
bool(false)
[E_WARNING] mysqlnd_ms_xa_begin(): php_network_getaddresses: getaddrinfo failed: %s in %s on line %d
[E_WARNING] mysqlnd_ms_xa_begin(): (mysqlnd_ms) MySQL XA state store error: php_network_getaddresses: getaddrinfo failed: %s in %s on line %d
bool(false)
done!