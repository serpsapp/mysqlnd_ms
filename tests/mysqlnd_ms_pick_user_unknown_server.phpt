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
if ($error = create_config("test_mysqlnd_ms_pick_user_unknown_server.ini", $settings))
	die(sprintf("SKIP %s\n", $error));
?>
--INI--
mysqlnd_ms.enable=1
mysqlnd_ms.ini_file=test_mysqlnd_ms_pick_user_unknown_server.ini
--FILE--
<?php
	require_once("connect.inc");

	function grumble_catchable_fatal_grumble($errno, $error, $file, $line) {
		static $errcodes = array();
		if (empty($errcodes)) {
			$constants = get_defined_constants();
			foreach ($constants as $name => $value) {
				if (substr($name, 0, 2) == "E_")
					$errcodes[$value] = $name;
			}
		}
		printf("[%s] %s in %s on line %s\n",
			(isset($errcodes[$errno])) ? $errcodes[$errno] : $errno,
			 $error, $file, $line);

		return true;
	}

	set_error_handler('grumble_catchable_fatal_grumble');

	function pick_server($connected_host, $query, $master, $slaves, $last_used_connection) {
		global $fail;
		printf("%s\n", $query);
		/* should default to build-in pick logic */
		if ($fail)
		  return "server that is not in master or slave list";
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
	if (!unlink("test_mysqlnd_ms_pick_user_unknown_server.ini"))
	  printf("[clean] Cannot unlink ini file 'test_mysqlnd_ms_pick_user_unknown_server.ini'.\n");
?>
--EXPECTF--
/*ms=master*/SELECT CONNECTION_ID() as _master FROM DUAL
[E_RECOVERABLE_ERROR] mysqli::query(): (mysqlnd_ms) User filter callback has returned an unknown server. The server 'server that is not in master or slave list' can neither be found in the master server list nor in the slave server list in %s on line %d
[002] [2014] Commands out of sync; you can't run this command now
/*ms=master*/SELECT CONNECTION_ID() as _master FROM DUAL
Master has thread id %d
done!