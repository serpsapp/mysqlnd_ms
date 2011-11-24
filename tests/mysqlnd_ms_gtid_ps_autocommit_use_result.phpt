--TEST--
PS, autocommit, GTID, stmt.use_result
--SKIPIF--
<?php
require_once('skipif.inc');
require_once("connect.inc");

_skipif_check_extensions(array("mysqli"));
_skipif_connect($master_host_only, $user, $passwd, $db, $master_port, $master_socket);
_skipif_connect($slave_host_only, $user, $passwd, $db, $slave_port, $slave_socket);

if (($master_host == $slave_host)) {
	die("SKIP master and slave seem to the the same, see tests/README");
}

include_once("util.inc");
$sql = mst_get_gtid_sql($db);
if ($error = mst_mysqli_setup_gtid_table($master_host_only, $user, $passwd, $db, $master_port, $master_socket))
  die(sprintf("SKIP Failed to setup GTID on master, %s\n", $error));

$settings = array(
	"myapp" => array(
		'master' => array($master_host),
		'slave' => array($slave_host),
		'filters' => array(
			"roundrobin" => array(),
		),
		'global_transaction_id_injection' => array(
			'on_commit'	 				=> $sql['update'],
			'report_error'				=> true,
		),
		'trx_stickiness' => 'disabled',
		'lazy_connections' => 1
	),
);
if ($error = mst_create_config("test_mysqlnd_ms_gtid_ps_autocommit_use_result.ini", $settings))
	die(sprintf("SKIP %s\n", $error));
?>
--INI--
mysqlnd_ms.enable=1
mysqlnd_ms.ini_file=test_mysqlnd_ms_gtid_ps_autocommit_use_result.ini
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

	if (!($link = mst_mysqli_connect("myapp", $user, $passwd, $db, $port, $socket)))
		printf("[001] [%d] %s\n", mysqli_connect_errno(), mysqli_connect_error());

	  $expected = array(
		"gtid_autocommit_injections_success" => 0,
		"gtid_autocommit_injections_failure" => 0,
		"gtid_commit_injections_success" => 0,
		"gtid_commit_injections_failure" => 0,
	);

	if (!$link->query("DROP TABLE IF EXISTS test") ||
		!$link->query("CREATE TABLE test(id INT) ENGINE=InnoDB"))
		printf("[002] [%d] %s\n", $link->errno, $link->error);

	$expected['gtid_autocommit_injections_success'] += 2;

	/* statement created in autocommit mode on master connection */
	if (!($stmt = $link->prepare(sprintf("/*%s*/SELECT COUNT(*) AS _num_rows FROM test", MYSQLND_MS_MASTER_SWITCH))))
		printf("[003] [%d] %s\n", $link->errno, $link->error);

	$stats = mysqlnd_ms_get_stats();
	compare_stats(4, $stats, $expected);

	if (!$stmt->execute())
		printf("[005] [%d] %s\n", $stmt->errno, $stmt->error);

	$expected['gtid_autocommit_injections_success']++;
	$stats = mysqlnd_ms_get_stats();
	compare_stats(6, $stats, $expected);

	$num_rows = NULL;
	if (!$stmt->bind_result($num_rows))
		printf("[007] [%d] %s\n", $stmt->errno, $stmt->error);

	if (!($res = $stmt->fetch()))
		printf("[008] [%d] %s\n", $stmt->errno, $stmt->error);

	printf("Rows %d\n", $num_rows);

	while ($stmt->fetch())
		printf("[009] Clean line...\n");

	if (!$link->query("INSERT INTO test(id) VALUES (1)"))
		printf("[010] [%d] %s\n", $link->errno, $link->error);

	$expected['gtid_autocommit_injections_success']++;
	$stats = mysqlnd_ms_get_stats();
	compare_stats(11, $stats, $expected);

	if (!$stmt->execute())
		printf("[012] [%d] %s\n", $stmt->errno, $stmt->error);

	$expected['gtid_autocommit_injections_success']++;
	$stats = mysqlnd_ms_get_stats();
	compare_stats(13, $stats, $expected);

	if (!($res = $stmt->fetch()))
		printf("[014] [%d] %s\n", $stmt->errno, $stmt->error);

	printf("Rows %d\n", $num_rows);

	while ($stmt->fetch())
		printf("[015] Clean line...\n");

	if (!$link->query("INSERT INTO test(id) VALUES (1)"))
		printf("[016] [%d] %s\n", $link->errno, $link->error);

	$expected['gtid_autocommit_injections_success']++;
	$stats = mysqlnd_ms_get_stats();
	compare_stats(17, $stats, $expected);

	if (!$stmt->execute())
		printf("[018] [%d] %s\n", $stmt->errno, $stmt->error);

	$expected['gtid_autocommit_injections_success']++;
	$stats = mysqlnd_ms_get_stats();
	compare_stats(19, $stats, $expected);

	if (!$stmt->execute())
		printf("[020] [%d] %s\n", $stmt->errno, $stmt->error);

	/* commands out of sync, injection prior execute failed */
	$expected['gtid_autocommit_injections_failure']++;
	$stats = mysqlnd_ms_get_stats();
	compare_stats(21, $stats, $expected);

	while ($stmt->fetch())
		printf("[022] Clean line...\n");

	printf("Rows %d\n", $num_rows);

	if (!$link->query("DROP TABLE IF EXISTS test"))
		printf("[023] [%d] %s\n", $link->errno, $link->error);

	$expected['gtid_autocommit_injections_success']++;
	$stats = mysqlnd_ms_get_stats();
	compare_stats(24, $stats, $expected);

	if (!$stmt->execute())
		printf("[025] [%d] %s\n", $stmt->errno, $stmt->error);

	/* injection is done before execute */
	$expected['gtid_autocommit_injections_success']++;
	$stats = mysqlnd_ms_get_stats();
	compare_stats(25, $stats, $expected);

	print "done!";
?>
--CLEAN--
<?php
	if (!unlink("test_mysqlnd_ms_gtid_ps_autocommit_use_result.ini"))
	  printf("[clean] Cannot unlink ini file 'test_mysqlnd_ms_gtid_ps_autocommit_use_result.ini'.\n");
?>
--EXPECTF--
Rows 0
Rows 1
[020] [0%A
[022] Clean line...
Rows 2
[025] [1146] %s
done!