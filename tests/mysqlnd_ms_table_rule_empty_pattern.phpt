--TEST--
table filter: rule with empty pattern
--SKIPIF--
<?php
require_once('skipif_mysqli.inc');
require_once("connect.inc");

$settings = array(
	"myapp" => array(
		'master' => array(
			"master1" => array(
				'host' 		=> $master_host_only,
				'port' 		=> (int)$master_port,
				'socket' 	=> $master_socket,
			),
			"master2" => array(
				'host'		=> 'Master_Thursday_1540_pm_really',
			),
		),
		'slave' => array(
			"slave1" => array(
				'host' 	=> $slave_host_only,
				'port' 	=> (int)$slave_port,
				'socket' => $slave_socket,
			),
			"master2" => array(
				'host'		=> 'Slave_Thursday_1540_pm_really',
			),
		 ),
		'lazy_connections' => 1,
		'filters' => array(
			"table" => array(
				"rules" => array(
					"" => array(
					  "master" => array("master2"),
					  "slave" => array("slave2"),
					),
					"%" => array(
					  "master" => array("master1"),
					  "slave" => array("slave1"),
					),
				),
			),
			"random" => array("sticky" => true),
		),
	),

);
if ($error = create_config("test_mysqlnd_ms_table_rule_empty_pattern.ini", $settings))
	die(sprintf("SKIP %s\n", $error));
?>
--INI--
mysqlnd_ms.enable=1
mysqlnd_ms.ini_file=test_mysqlnd_ms_table_rule_empty_pattern.ini
mysqlnd_ms.multi_master=1
--FILE--
<?php
	require_once("connect.inc");
	require_once("mysqlnd_ms_lazy.inc");

	$link = my_mysqli_connect("myapp", $user, $passwd, $db, $port, $socket);
	if (mysqli_connect_errno()) {
		printf("[001] [%d] %s\n", mysqli_connect_errno(), mysqli_connect_error());
	}

	/* valid config or not? */
	verbose_run_query(2, $link, "DROP TABLE IF EXISTS test");
	if (0 == $link->thread_id)
		printf("[003] Not connected to any server.");

	print "done!";
?>
--CLEAN--
<?php
	if (!unlink("test_mysqlnd_ms_table_rule_empty_pattern.ini"))
	  printf("[clean] Cannot unlink ini file 'test_mysqlnd_ms_table_rule_empty_pattern.ini'.\n");
?>
--EXPECTF--
Fatal error: mysqli_real_connect(): (mysqlnd_ms) A table filter must be given a name. You must not use an empty string in %s on line %d