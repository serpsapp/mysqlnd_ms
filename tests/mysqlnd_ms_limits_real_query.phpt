--TEST--
Limits - real_query is NOT handled by the prototype
--SKIPIF--
<?php
require_once('skipif.inc');
require_once("connect.inc");

if ($master_host == $slave_host) {
	die("SKIP master and slave seem to the the same, see tests/README");
}

$settings = array(
	"myapp" => array(
		'master' => array($master_host),
		'slave' => array($slave_host, $slave_host),
	),
);
if ($error = create_config("test_mysqlnd_real_query.ini", $settings))
	die(sprintf("SKIP %d\n", $error));

?>
--INI--
mysqlnd_ms.enable=1
mysqlnd_ms.ini_file=test_mysqlnd_real_query.ini
--FILE--
<?php
	require_once("connect.inc");

	function run_query($offset, $link, $query, $switch = NULL) {
		if ($switch)
			$query = sprintf("/*%s*/%s", $switch, $query);

		if (!($ret = $link->real_query($query)))
			printf("[%03d] [%d] %s\n", $offset, $link->errno, $link->error);

		return $ret;
	}

	if (!($link = my_mysqli_connect($host, $user, $passwd, $db, $port, $socket)))
		printf("[001] [%d] %s\n", mysqli_connect_errno($link), mysqli_connect_error($link));

	run_query(2, $link, "SET @myrole='slave1'", MYSQLND_MS_SLAVE_SWITCH);
	run_query(3, $link, "SET @myrole='slave2'", MYSQLND_MS_SLAVE_SWITCH);
	run_query(4, $link, "SET @myrole='master'", MYSQLND_MS_MASTER_SWITCH);

	/* round robin - slave 1 ? No, real_query is not handled! the master will reply! */
	run_query(5, $link, "SELECT @myrole AS _role", MYSQLND_MS_SLAVE_SWITCH);
	if (!$res = mysqli_use_result($link)) {
		printf("[006] [%d] %s\n", $link->errno, $link->error);
	}
	while ($row = $res->fetch_assoc())
		if ($row['_role'] != 'slave1')
			printf("[007] Expecting 'slave1' got '%s'\n", $row['_role']);

	$res->close();

	run_query(8, $link, "DROP TABLE IF EXISTS test", MYSQLND_MS_LAST_USED_SWITCH);
	run_query(9, $link, "CREATE TABLE test(id INT, label varchar(20))", MYSQLND_MS_LAST_USED_SWITCH);
	run_query(10, $link, "INSERT INTO test(id, label) VALUES (1, 'a'), (2, 'b'), (3, 'c')", MYSQLND_MS_LAST_USED_SWITCH);
	run_query(11, $link, "SELECT @myrole AS _role, id, label FROM test ORDER BY id ASC", MYSQLND_MS_LAST_USED_SWITCH);

	if (!$res = mysqli_use_result($link)) {
		printf("[012] [%d] %s\n", $link->errno, $link->error);
	}
	while ($row = $res->fetch_assoc())
	  printf("Slave 1, field_count = %d, role = %s, id = %d, label = '%s'\n",
		$res->field_count,
		$row['_role'], $row['id'], $row['label']);

	print "done!";
?>
--CLEAN--
<?php
	if (!unlink("test_mysqlnd_real_query.ini"))
	  printf("[clean] Cannot unlink ini file 'test_mysqlnd_ms_ini_force_config.ini'.\n");
?>
--EXPECTF--
[007] Expecting 'slave1' got 'master'
Slave 1, field_count = 3, role = master, id = 1, label = 'a'
Slave 1, field_count = 3, role = master, id = 2, label = 'b'
Slave 1, field_count = 3, role = master, id = 3, label = 'c'
done!