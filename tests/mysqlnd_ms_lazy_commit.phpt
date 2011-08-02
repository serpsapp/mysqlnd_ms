--TEST--
lazy connections and commit
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
		),

		'slave' => array(
			"slave1" => array(
				'host' 	=> $slave_host_only,
				'port' 	=> (int)$slave_port,
				'socket' => $slave_socket,
			),
		 ),

		'lazy_connections' => 1,
		'filters' => array(
			"random" => array('sticky' => '1'),
		),
	),

);
if ($error = create_config("test_mysqlnd_ms_lazy_commit.ini", $settings))
	die(sprintf("SKIP %s\n", $error));
?>
--INI--
mysqlnd_ms.enable=1
mysqlnd_ms.ini_file=test_mysqlnd_ms_lazy_commit.ini
--FILE--
<?php
	require_once("connect.inc");
	require_once("mysqlnd_ms_lazy.inc");

	$link = my_mysqli_connect("myapp", $user, $passwd, $db, $port, $socket);
	if (mysqli_connect_errno()) {
		printf("[002] [%d] %s\n", mysqli_connect_errno(), mysqli_connect_error());
	}

	if (!$link->dump_debug_info())
		printf("[003] [%d] %s\n", $link->errno, $link->error);

	if (!$link->commit())
		printf("[004] [%d] %s\n", $link->errno, $link->error);
	else
		printf("[004] Commit\n");

	if (!$link->dump_debug_info())
		printf("[005] [%d] %s\n", $link->errno, $link->error);

	if ($res = run_query(6, $link, "SELECT 1 FROM DUAL"))
		var_dump($res->fetch_assoc());


	print "done!";
?>
--CLEAN--
<?php
	require_once("connect.inc");

	if (!unlink("test_mysqlnd_ms_lazy_commit.ini"))
	  printf("[clean] Cannot unlink ini file 'test_mysqlnd_ms_lazy_commit.ini'.\n");
?>
--EXPECTF--
[003] [%d] %s
[004] [%d] %s
[005] [%d] %s
array(1) {
  [1]=>
  string(1) "1"
}
done!