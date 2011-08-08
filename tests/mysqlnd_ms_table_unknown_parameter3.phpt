--TEST--
table filter: unknown parameter, name \0
--SKIPIF--
<?php
require_once('skipif.inc');
require_once("connect.inc");

_skipif_check_extensions(array("mysqli"));
_skipif_connect($master_host_only, $user, $passwd, $db, $master_port, $master_socket);
_skipif_connect($slave_host_only, $user, $passwd, $db, $slave_port, $slave_socket);

$settings = array(
	"myapp" => array(
		'master' => array(
			"master1" => array(
				'host' 		=> $master_host_only,
				'port' 		=> (int)$master_port,
				'socket' 	=> $master_socket,
			),
			"master2" => array( "host" => "running_out_of_silly_names"),
		),
		'slave' => array(
			"slave1" => array(
				'host' 	=> $slave_host_only,
				'port' 	=> (int)$slave_port,
				'socket' => $slave_socket,
			),
			"slave2" => array( "host" => "running_out_of_silly_names"),
		 ),
		'lazy_connections' => 1,
		'filters' => array(
			"table" => array(
				"\0" => array(
					"best.%" => array(
					  "master" => array("master2"),
					  "slave" => array("slave2"),
					),
				),
				"rules" => array(
					$db . ".%" => array(
					  "master" => array("master1"),
					  "slave" => array("slave1"),
					),
				),
			),
			"roundrobin" => array(),
		),
	),

);
if ($error = create_config("test_mysqlnd_ms_table_unknown_parameter3.ini", $settings))
	die(sprintf("SKIP %s\n", $error));
?>
--INI--
mysqlnd_ms.enable=1
mysqlnd_ms.ini_file=test_mysqlnd_ms_table_unknown_parameter3.ini
--FILE--
<?php
	require_once("connect.inc");
	require_once("mysqlnd_ms_lazy.inc");

	$link = my_mysqli_connect("myapp", $user, $passwd, $db, $port, $socket);
	if (mysqli_connect_errno()) {
		printf("[001] [%d] %s\n", mysqli_connect_errno(), mysqli_connect_error());
	}

	run_query(2, $link, "DROP TABLE IF EXISTS test");
	if ($link->thread_id == 0)
		printf("[003] Which server has run this?");

	run_query(4, $link, "DROP TABLE IF EXISTS test", MYSQLND_MS_SLAVE_SWITCH);
	if ($link->thread_id == 0)
		printf("[005] Which server has run this?");

	print "done!";
?>
--CLEAN--
<?php
	if (!unlink("test_mysqlnd_ms_table_unknown_parameter3.ini"))
	  printf("[clean] Cannot unlink ini file 'test_mysqlnd_ms_table_unknown_parameter3.ini'.\n");
?>
--EXPECTF--
done!