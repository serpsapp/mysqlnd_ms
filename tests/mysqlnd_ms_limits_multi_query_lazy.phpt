--TEST--
multi query and lazy connections
--SKIPIF--
<?php
require_once('skipif.inc');
require_once("connect.inc");

_skipif_check_extensions(array("mysqli"));
_skipif_connect($master_host_only, $user, $passwd, $db, $master_port, $master_socket);
_skipif_connect($slave_host_only, $user, $passwd, $db, $slave_port, $slave_socket);

$settings = array(
	$host => array(
		'master' => array($master_host),
		'slave' => array($slave_host),
		'pick' => array("roundrobin"),
		'lazy_connections' => 1,
	),
);
if ($error = create_config("test_mysqlnd_ms_limits_multi_query_lazy.ini", $settings))
	die(sprintf("SKIP %s\n", $error));

?>
--INI--
mysqlnd_ms.enable=1
mysqlnd_ms.ini_file=test_mysqlnd_ms_limits_multi_query_lazy.ini
--FILE--
<?php
	require_once("connect.inc");

	function run_query($offset, $link, $query, $switch = NULL) {
		if ($switch)
			$query = sprintf("/*%s*/%s", $switch, $query);

		if (!($ret = $link->multi_query($query)))
			printf("[%03d] [%d] %s\n", $offset, $link->errno, $link->error);

		return $ret;
	}

	if (!($link = my_mysqli_connect($host, $user, $passwd, $db, $port, $socket)))
		printf("[001] [%d] %s\n", mysqli_connect_errno(), mysqli_connect_error());

	run_query(2, $link, "SET @myrole='Slave 1'", MYSQLND_MS_SLAVE_SWITCH);
	run_query(4, $link, "SET @myrole='Master 1'");
	/* slave 1 */
	run_query(5, $link, "SELECT 'This is ' AS _msg FROM DUAL; SELECT @myrole AS _msg; SELECT ' speaking!' AS _msg FROM DUAL");

	do {
		if ($res = $link->store_result()) {
			$row = $res->fetch_assoc();
			printf("%s", $row['_msg']);
			$res->free();
		}
	} while ($link->more_results() && $link->next_result());
	echo "\n";


	print "done!";

?>
--CLEAN--
<?php
	if (!unlink("test_mysqlnd_ms_limits_multi_query_lazy.ini"))
	  printf("[clean] Cannot unlink ini file 'test_mysqlnd_ms_limits_multi_query_lazy.ini'.\n");
?>
--EXPECTF--

[005] [0]%s

done!