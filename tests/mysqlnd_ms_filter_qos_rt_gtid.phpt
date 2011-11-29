--TEST--
Filter QOS, runtime, session GTID
--SKIPIF--
<?php
if (version_compare(PHP_VERSION, '5.3.99-dev', '<'))
	die(sprintf("SKIP Requires PHP >= 5.3.99, using " . PHP_VERSION));

require_once('skipif.inc');
require_once("connect.inc");

if (($master_host == $slave_host)) {
	die("SKIP master and slave seem to the the same, see tests/README");
}

_skipif_check_extensions(array("mysqli"));
_skipif_connect($master_host_only, $user, $passwd, $db, $master_port, $master_socket);
_skipif_connect($slave_host_only, $user, $passwd, $db, $slave_port, $slave_socket);

include_once("util.inc");
$sql = mst_get_gtid_sql($db);
if ($error = mst_mysqli_setup_gtid_table($master_host_only, $user, $passwd, $db, $master_port, $master_socket))
  die(sprintf("SKIP Failed to setup GTID on master, %s\n", $error));


$settings = array(
	"myapp" => array(
		'master' => array(
			"master1" => array(
				'host' 		=> $master_host_only,
				'port' 		=> (int)$master_port,
				'socket' 	=> $master_socket,
			),
		),
		'slave' => array(
			"slave1" => array(
				'host' 	=> $slave_host_only,
				'port' 	=> (int)$slave_port,
				'socket' => $slave_socket,
			),
		 ),

		'lazy_connections' => 0,

		'global_transaction_id_injection' => array(
			'on_commit'	 				=> $sql['update'],
			'fetch_last_gtid'			=> $sql['fetch_last_gtid'],
			'check_for_gtid'			=> $sql['check_for_gtid'],
			'report_error'				=> true,
		),

	),

);
if ($error = mst_create_config("test_mysqlnd_ms_filter_qos_rt_gtid.ini", $settings))
	die(sprintf("SKIP %s\n", $error));

msg_mysqli_init_emulated_id_skip($slave_host, $user, $passwd, $db, $slave_port, $slave_socket, "slave1");
msg_mysqli_init_emulated_id_skip($master_host, $user, $passwd, $db, $master_port, $master_socket, "master1");
?>
--INI--
mysqlnd_ms.enable=1
mysqlnd_ms.ini_file=test_mysqlnd_ms_filter_qos_rt_gtid.ini
--FILE--
<?php
	require_once("connect.inc");
	require_once("util.inc");

	$link = new mysqli("myapp", $user, $passwd, $db, $port, $socket);
	if (mysqli_connect_errno()) {
		printf("[001] [%d] %s\n", mysqli_connect_errno(), mysqli_connect_error());
	}

	if (!$link->query("DROP TABLE IF EXISTS test") ||
		!$link->query("CREATE TABLE test(id INT) ENGINE=InnoDB") ||
		!$link->query("INSERT INTO test(id) VALUES (1)")) {
		printf("[002] [%d] %s\n", $link->errno, $link->error);
	}

	$master_id = mst_mysqli_get_emulated_id(3, $link);
	if ($res = mst_mysqli_query(4, $link, "SELECT id FROM test", MYSQLND_MS_MASTER_SWITCH)) {
		var_dump($res->fetch_all());
	}

	if (false === ($gtid = mysqlnd_ms_get_last_gtid($link)))
		printf("[005] [%d] %s\n", $link->errno, $link->error);

	printf("GTID '%s'\n", $gtid);

	if (false == mysqlnd_ms_set_qos($link, MYSQLND_MS_QOS_CONSISTENCY_SESSION, MYSQLND_MS_QOS_OPTION_GTID, $gtid)) {
		printf("[006] [%d] %s\n", $link->errno, $link->error);
	}

	if ($res = mst_mysqli_query(7, $link, "SELECT id FROM test")) {
		var_dump($res->fetch_all());
	}
	$server_id = mst_mysqli_get_emulated_id(8, $link);
	/* either master or slave depending on test setup. In any case result from select must be correct */
	printf("[009] Run on %s\n", $server_id);

	print "done!";
?>
--CLEAN--
<?php
	if (!unlink("test_mysqlnd_ms_filter_qos_rt_gtid.ini"))
	  printf("[clean] Cannot unlink ini file 'test_mysqlnd_ms_filter_qos_rt_gtid.ini'.\n");

	require_once("connect.inc");
	require_once("util.inc");
	if ($error = mst_mysqli_drop_test_table($master_host_only, $user, $passwd, $db, $master_port, $master_socket))
		printf("[clean] %s\n");

	if ($error = mst_mysqli_drop_gtid_table($master_host_only, $user, $passwd, $db, $master_port, $master_socket))
		printf("[clean] %s\n", $error));
?>
--EXPECTF--
array(1) {
  [0]=>
  array(1) {
    [0]=>
    string(1) "1"
  }
}
GTID '%d'
array(1) {
  [0]=>
  array(1) {
    [0]=>
    string(1) "1"
  }
}
[009] Run on %s
done!