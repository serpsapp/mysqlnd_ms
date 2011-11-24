--TEST--
GTID and report errors on
--SKIPIF--
<?php
if (version_compare(PHP_VERSION, '5.3.99-dev', '<'))
	die(sprintf("SKIP Requires PHP >= 5.3.99, using " . PHP_VERSION));

require_once('skipif.inc');
  require_once("connect.inc");

_skipif_check_extensions(array("mysqli"));
_skipif_connect($master_host_only, $user, $passwd, $db, $master_port, $master_socket);
_skipif_connect($slave_host_only, $user, $passwd, $db, $slave_port, $slave_socket);

include_once("util.inc");
$sql = mst_get_gtid_sql($db);

$link = mst_mysqli_connect($master_host_only, $user, $passwd, $db, $master_port, $master_socket);
if (mysqli_connect_errno())
	die(sprintf("SKIP [%d] %s\n", mysqli_connect_errno(), mysqli_connect_error()));
if (!$link->query($sql['drop']))
	die(sprintf("SKIP [%d] %s\n", $link->errno, $link->error));

$link = mst_mysqli_connect($slave_host_only, $user, $passwd, $db, $slave_port, $slave_socket);
if (mysqli_connect_errno())
	die(sprintf("SKIP [%d] %s\n", mysqli_connect_errno(), mysqli_connect_error()));
if (!$link->query($sql['drop']))
	die(sprintf("SKIP [%d] %s\n", $link->errno, $link->error));

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

		'global_transaction_id_injection' => array(
			'on_commit'	 				=> $sql['update'],
			'report_error'				=> true,
			'set_on_slave'				=> true,
		),

		'lazy_connections' => 1,
		'trx_stickiness' => 'disabled',
		'filters' => array(
			"roundrobin" => array(),
		),
	),

);
if ($error = mst_create_config("test_mysqlnd_ms_gtid_report_errors_on.ini", $settings))
	die(sprintf("SKIP %s\n", $error));
?>
--INI--
mysqlnd_ms.enable=1
mysqlnd_ms.ini_file=test_mysqlnd_ms_gtid_report_errors_on.ini
mysqlnd_ms.collect_statistics=1
--FILE--
<?php
	require_once("connect.inc");
	require_once("util.inc");

	function compare_stats($offset, $stats, $expected) {
		foreach ($stats as $name => $value) {
			if (isset($expected[$name])) {
				if ($value != $expected[$name]) {
					printf("[%03d] Expecting %s = %d got %d\n", $offset, $name, $expected[$name], $value);
				}
				unset($expected[$name]);
			}
		}
		if (!empty($expected)) {
			printf("[%03d] Dumping list of missing stats\n", $offset);
			var_dump($expected);
		}
	}

	$link = mst_mysqli_connect("myapp", $user, $passwd, $db, $port, $socket);
	if (mysqli_connect_errno()) {
		printf("[002] [%d] %s\n", mysqli_connect_errno(), mysqli_connect_error());
	}

	$expected = array(
		"gtid_autocommit_injections_success" => 0,
		"gtid_autocommit_injections_failure" => 0,
		"gtid_commit_injections_success" => 0,
		"gtid_commit_injections_failure" => 0,
	);
	$stats = mysqlnd_ms_get_stats();
	compare_stats(4, $stats, $expected);

	/* auto commit on (default) */
	mst_mysqli_query(5, $link, "SET @myrole='master'");
	$expected['gtid_autocommit_injections_failure']++;
	mst_mysqli_query(7, $link, "SET @myrole'slave'", MYSQLND_MS_SLAVE_SWITCH);
	$expected['gtid_autocommit_injections_failure']++;

	$stats = mysqlnd_ms_get_stats();
	compare_stats(9, $stats, $expected);

	$link->autocommit(false);

	/* SET should have not been executed */
	if (!$res = mst_mysqli_query(10, $link, "SELECT @myrole AS _role"))
		printf("[012] %d %s\n", $link->errno, $link->error);
	$row = $res->fetch_assoc();
	printf("[013] Slave says '%s'\n", $row['_role']);

	if (!$res = mst_mysqli_query(14, $link, "SELECT @myrole AS _role", MYSQLND_MS_MASTER_SWITCH))
		printf("[016] %d %s\n", $link->errno, $link->error);
	$row = $res->fetch_assoc();
	printf("[017] Master says '%s'\n", $row['_role']);

	if (!$res = mst_mysqli_query(18, $link, "SELECT @myrole AS _role", MYSQLND_MS_LAST_USED_SWITCH))
		printf("[020] %d %s\n", $link->errno, $link->error);
	$row = $res->fetch_assoc();
	printf("[021] Master says again '%s'\n", $row['_role']);

	mst_mysqli_query(22, $link, "SET @myrole='master'");
	if ($link->commit())
		printf("[024] Commit should have failed\n");
	else
		printf("[025] [%d] %s\n", $link->errno, $link->error);
	$expected['gtid_commit_injections_failure']++;

	$res = mst_mysqli_query(26, $link, "SELECT 1 AS _one FROM DUAL");
	$row = $res->fetch_assoc();
	printf("Slave says '%d'\n", $row['_one']);

	if ($link->commit())
		printf("[028] Commit should have failed\n");
	else
		printf("[029] [%d] %s\n", $link->errno, $link->error);
	$expected['gtid_commit_injections_failure']++;

	$res = mst_mysqli_query(30, $link, "SELECT 2 AS _two FROM DUAL", MYSQLND_MS_MASTER_SWITCH);
	$row = $res->fetch_assoc();
	printf("Master says '%d'\n", $row['_two']);

	if ($link->commit())
		printf("[032] Commit should have failed\n");
	else
		printf("[033] [%d] %s\n", $link->errno, $link->error);
	$expected['gtid_commit_injections_failure']++;

	$stats = mysqlnd_ms_get_stats();
	compare_stats(34, $stats, $expected);

	$link->autocommit(true);

	/* Note: we inject before the original query, thus we see the inection error */
	mst_mysqli_query(36, $link, "SET MY LIFE ON FIRE");
	$expected['gtid_autocommit_injections_failure']++;
	mst_mysqli_query(38, $link, "SET MY LIFE ON FIRE", MYSQLND_MS_MASTER_SWITCH);
	$expected['gtid_autocommit_injections_failure']++;

	$sql = mst_get_gtid_sql($db);
	if ($error = mst_mysqli_setup_gtid_table($master_host_only, $user, $passwd, $db, $master_port, $master_socket))
		printf("[040] %s\n", $error);

	if ($error = mst_mysqli_setup_gtid_table($slave_host_only, $user, $passwd, $db, $slave_port, $slave_socket))
		printf("[041] %s\n", $error);

	mst_mysqli_query(42, $link, "SET MY LIFE ON FIRE");
	$expected['gtid_autocommit_injections_success']++;
	mst_mysqli_query(44, $link, "SET MY LIFE ON FIRE", MYSQLND_MS_MASTER_SWITCH);
	$expected['gtid_autocommit_injections_success']++;

	$stats = mysqlnd_ms_get_stats();
	compare_stats(45, $stats, $expected);

	if ($error = mst_mysqli_setup_gtid_table($master_host_only, $user, $passwd, $db, $master_port, $master_socket))
		printf("[046] %s\n", $error);

	if ($error = mst_mysqli_setup_gtid_table($slave_host_only, $user, $passwd, $db, $slave_port, $slave_socket))
		printf("[047] %s\n", $error);

	$link->autocommit(false);

	mst_mysqli_query(48, $link, "SET MY LIFE ON FIRE");
	mst_mysqli_query(50, $link, "SET MY LIFE ON FIRE", MYSQLND_MS_MASTER_SWITCH);


	print "done!";
?>
--CLEAN--
<?php
	if (!unlink("test_mysqlnd_ms_gtid_report_errors_on.ini"))
	  printf("[clean] Cannot unlink ini file 'test_mysqlnd_ms_gtid_report_errors_on.ini'.\n");
?>
--EXPECTF--
[005] [1146] %s
[007] [1146] %s
[013] Slave says ''
[017] Master says ''
[021] Master says again ''
[025] [1146] %s
Slave says '1'
[029] [1146] %s
Master says '2'
[033] [1146] %s
[036] [1146] %s
[038] [1146] %s
[042] [1193] %s
[044] [1193] %s
[048] [1193] %s
[050] [1193] %s
done!