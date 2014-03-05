--TEST--
Fabric: sharding.lookup_servers command
--SKIPIF--
<?php
require_once('skipif.inc');
require_once("connect.inc");

if (!getenv("MYSQL_TEST_FABRIC")) {
	die(sprintf("SKIP Fabric - set MYSQL_TEST_FABRIC=1 (config.inc) to enable\n"));
}

$settings = array(
	"myapp" => array(
		'fabric' => array(
			'hosts' => array(
						array('host' => '127.0.0.1', 'port' => '8080')
					)
		)
	),
);
if ($error = mst_create_config("test_mysqlnd_ms_fabric_cmd_sharding_lookup_servers.ini", $settings))
  die(sprintf("SKIP %s\n", $error));
?>
--INI--
mysqlnd_ms.enable=1
mysqlnd_ms.config_file=test_mysqlnd_ms_fabric_cmd_sharding_lookup_servers.ini
mysqlnd_ms.collect_statistics=1
--FILE--
<?php
	require_once("connect.inc");
	require_once("util.inc");

	$stats = mysqlnd_ms_get_stats();

	$link = mst_mysqli_connect("myapp", $user, $passwd, $db, $port, $socket);
	if (0 !== mysqli_connect_errno())
		printf("[001] [%d] %s\n", mysqli_connect_errno(), mysqli_connect_error());

	/* Would be surprised if anybody set a mapping for table=DUAL... */
	var_dump(mysqlnd_ms_fabric_select_global($link, "DUAL"));
	var_dump($link->error);

	$now = mysqlnd_ms_get_stats();

	foreach ($stats as $k => $v) {
		if ($now[$k] != $v) {
			printf("%s: %s -> %s\n", $k, $v, $now[$k]);
		}
	}
	print "done!";
?>
--CLEAN--
<?php
	if (!unlink("test_mysqlnd_ms_fabric_cmd_sharding_lookup_servers.ini"))
	  printf("[clean] Cannot unlink ini file 'test_mysqlnd_ms_fabric_cmd_sharding_lookup_servers.ini'.\n");
?>
--EXPECTF--
Warning: mysqlnd_ms_fabric_select_global(): (mysqlnd_ms) %s in %s on line %d
bool(false)
string(0) ""
fabric_sharding_lookup_servers_success: 0 -> 1
fabric_sharding_lookup_servers_time_total: 0 -> %d
fabric_sharding_lookup_servers_bytes_total: 0 -> %d
fabric_sharding_lookup_servers_xml_failure: 0 -> 1
done!