--TEST--
table filter: rule defined twice, invalid hosts first
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
				 'host' 	=> "I_really_hope_this_does_and_so_forth",
			),
		),
		'slave' => array(
			"slave1" => array(
				'host' 	=> $slave_host_only,
				'port' 	=> (int)$slave_port,
				'socket' => $slave_socket,
			),
			"slave2" => array(
				 'host' 	=> "I_really_hope_this_does_and_so_forth",
			),
		 ),
		'lazy_connections' => 1,
		'filters' => array(
			"table" => array(
				"rules" => array(
					$db . ".%" => array(
					  "master" => array("master2"),
					  "slave" => array("slave2"),
					),
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
if ($error = create_config("test_mysqlnd_ms_table_rule_twice2.ini", $settings))
	die(sprintf("SKIP %s\n", $error));
?>
--INI--
mysqlnd_ms.enable=1
mysqlnd_ms.ini_file=test_mysqlnd_ms_table_rule_twice2.ini
--FILE--
<?php
	require_once("connect.inc");
	require_once("mysqlnd_ms_lazy.inc");

	$link = my_mysqli_connect("myapp", $user, $passwd, $db, $port, $socket);
	if (mysqli_connect_errno()) {
		printf("[001] [%d] %s\n", mysqli_connect_errno(), mysqli_connect_error());
	}

	print "done!";
?>
--CLEAN--
<?php
	if (!unlink("test_mysqlnd_ms_table_rule_twice2.ini"))
	  printf("[clean] Cannot unlink ini file 'test_mysqlnd_ms_table_rule_twice2.ini'.\n");
?>
--EXPECTF--
[001] [%d] %s
done!