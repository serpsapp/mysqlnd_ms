--TEST--
Config settings: pick server = user, unknown server
--SKIPIF--
<?php
require_once('skipif_mysqli.inc');
require_once("connect.inc");

$settings = array(
	"myapp" => array(
		'master' => array($master_host),
		'slave' => array($slave_host),
		'pick' 	=> array('user' => array('callback' => 'pick_server')),
	),
);
if ($error = create_config("test_mysqlnd_ms_pick_user_return_void.ini", $settings))
	die(sprintf("SKIP %s\n", $error));
?>
--INI--
mysqlnd_ms.enable=1
mysqlnd_ms.ini_file=test_mysqlnd_ms_pick_user_return_void.ini
--FILE--
<?php
	require_once("connect.inc");
	require_once("mysqlnd_ms_pick_user.inc");

	function pick_server($connected_host, $query, $master, $slaves, $last_used_connection) {
		global $fail;
		printf("%s\n", $query);
		/* should default to build-in pick logic */
		if ($fail)
		  return;
		return $master[0];
	}

	if (!$link = my_mysqli_connect("myapp", $user, $passwd, $db, $port, $socket))
		printf("[001] Cannot connect to the server using host=%s, user=%s, passwd=***, dbname=%s, port=%s, socket=%s\n",
			$host, $user, $db, $port, $socket);

	/* Catchable fatal error, no server selected */
	$fail = true;
	$query = sprintf("/*%s*/SELECT CONNECTION_ID() as _master FROM DUAL", MYSQLND_MS_MASTER_SWITCH);
	/* random follow-up error message, e.g. 2014 Commands out of sync */
	if (!$res = $link->query($query))
		printf("[002] [%d] %s\n", $link->errno, $link->error);


	/* The connection is still useable. Just rerun the statement and pick a connection from the pool */
	$fail = false;
	$query = sprintf("/*%s*/SELECT CONNECTION_ID() as _master FROM DUAL", MYSQLND_MS_MASTER_SWITCH);
	/* random follow-up error message, e.g. 2014 Commands out of sync */
	if (!$res = $link->query($query))
		printf("[003] [%d] %s\n", $link->errno, $link->error);

	$row = $res->fetch_assoc();
	$res->close();
	printf("Master has thread id %d\n", $row['_master']);

	print "done!";
?>
--CLEAN--
<?php
	if (!unlink("test_mysqlnd_ms_pick_user_return_void.ini"))
	  printf("[clean] Cannot unlink ini file 'test_mysqlnd_ms_pick_user_return_void.ini'.\n");
?>
--EXPECTF--
/*ms=master*/SELECT CONNECTION_ID() as _master FROM DUAL
[E_RECOVERABLE_ERROR] mysqli::query(): (mysqlnd_ms) User filter callback has not returned string with server to use. The callback must return a string in %s on line %d
[002] [2014] Commands out of sync; you can't run this command now
/*ms=master*/SELECT CONNECTION_ID() as _master FROM DUAL
Master has thread id %d
done!