--TEST--
insert id, affected rows
--SKIPIF--
<?php
require_once('skipif.inc');
if (!extension_loaded("pdo_mysql"))
  die("SKIP ext/pdo_mysql not available");

require_once("connect.inc");

$settings = array(
	"myapp" => array(
		'master' => array($master_host),
		'slave' => array($slave_host, $slave_host),
		'pick' => array("roundrobin"),
	),
);
if ($error = create_config("test_mysqlnd_insert_affected_pdo.ini", $settings))
	die(sprintf("SKIP %d\n", $error));

?>
--INI--
mysqlnd_ms.enable=1
mysqlnd_ms.ini_file=test_mysqlnd_insert_affected_pdo.ini
--FILE--
<?php
	require_once("connect.inc");

	function run_query($offset, $pdo, $query, $switch = NULL) {
		if ($switch)
			$query = sprintf("/*%s*/%s", $switch, $query);

		return $pdo->exec($query);
	}

	function run_insert($offset, $pdo, $num_rows, $switch = NULL) {
		run_query($offset, $pdo, "DROP TABLE IF EXISTS test", $switch);
		run_query($offset + 1, $pdo, "CREATE TABLE test(id INT AUTO_INCREMENT PRIMARY KEY, label CHAR(1))", MYSQLND_MS_LAST_USED_SWITCH);

		for ($i = 0; $i < $num_rows; $i++) {
			run_query($offset + 2, $pdo, "INSERT INTO test(label) VALUES ('a')", MYSQLND_MS_LAST_USED_SWITCH);
		}
	}

	try {
		$pdo = my_pdo_connect("myapp", $user, $passwd, $db, $port, $socket);
	} catch (Exception $e) {
		printf("[001] %s\n", $e->getMessage());
	}

	/* master, automatically */
	try {
		run_insert(10, $pdo, 1);
		if (1 != $pdo->lastInsertId())
		  printf("[11] Master insert id should be 1 got %d\n", $pdo->lastInsertId());

		$affected = run_query(12, $pdo, "UPDATE test SET label = 'b'", MYSQLND_MS_LAST_USED_SWITCH);
		if (1 !== $affected)
		  printf("[13] Master affected should be 1 got %d\n", $affected);

	} catch (Exception $e) {
		printf("[014] %s\n", $e->getMessage());
	}

	/* slave 1  */
	try {
		run_insert(20, $pdo, 5, MYSQLND_MS_SLAVE_SWITCH);
		if (5 != $pdo->lastInsertId())
		  printf("[21] Slave 1 insert id should be 5 got %d\n", $pdo->lastInsertId());

		$affected = run_query(22, $pdo, "UPDATE test SET label = 'b'", MYSQLND_MS_LAST_USED_SWITCH);
		if (5 !== $affected)
		  printf("[23] Slave 1 affected should be 5 got %d\n", $affected);

	} catch (Exception $e) {
		printf("[014] %s\n", $e->getMessage());
	}

	print "done!";

?>
--CLEAN--
<?php
	if (!unlink("test_mysqlnd_insert_affected_pdo.ini"))
	  printf("[clean] Cannot unlink ini file 'test_mysqlnd_insert_affected_pdo.ini'.\n");
?>
--EXPECTF--
done!