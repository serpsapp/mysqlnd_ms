--TEST--
Charsets, choosing invalid
--SKIPIF--
<?php
require_once('skipif.inc');
require_once("connect.inc");

_skipif_check_extensions(array("mysqli"));
_skipif_connect($master_host_only, $user, $passwd, $db, $master_port, $master_socket);
_skipif_connect($slave_host_only, $user, $passwd, $db, $slave_port, $slave_socket);

$settings = array(
	"myapp" => array(
		'master' => array($master_host),
		'slave' => array($slave_host),
	),
);
if ($error = create_config("test_mysqlnd_ms_charsets_fail.ini", $settings))
	die(sprintf("SKIP %s\n", $error));

function test_for_charset($host, $user, $passwd, $db, $port, $socket) {
	if (!$link = my_mysqli_connect($host, $user, $passwd, $db, $port, $socket))
		die(sprintf("skip Cannot connect, [%d] %s", mysqli_connect_errno(), mysqli_connect_error()));

	if (!($res = mysqli_query($link, 'SELECT version() AS server_version')) ||
			!($tmp = mysqli_fetch_assoc($res))) {
		mysqli_close($link);
		die(sprintf("skip Cannot check server version, [%d] %s\n",
		mysqli_errno($link), mysqli_error($link)));
	}
	mysqli_free_result($res);
	$version = explode('.', $tmp['server_version']);
	if (empty($version)) {
		mysqli_close($link);
		die(sprintf("skip Cannot check server version, based on '%s'",
			$tmp['server_version']));
	}

	if ($version[0] <= 4 && $version[1] < 1) {
		mysqli_close($link);
		die(sprintf("skip Requires MySQL Server 4.1+\n"));
	}

	if (($res = mysqli_query($link, 'SHOW CHARACTER SET LIKE "pleasenot"', MYSQLI_STORE_RESULT)) && (mysqli_num_rows($res) == 1)) {
		die(sprintf("skip WOW, server has charset 'pleasenot'!\n"));
	}

	if (!$res = mysqli_query($link, 'SELECT @@character_set_connection AS charset'))
		die(sprintf("skip Cannot select current charset, [%d] %s\n", $link->errno, $link->error));

	if (!$row = mysqli_fetch_assoc($res))
		die(sprintf("skip Cannot detect current charset, [%d] %s\n", $link->errno, $link->error));

	return $row['charset'];
}

test_for_charset($master_host_only, $user, $passwd, $db, $master_port, $master_socket);
test_for_charset($slave_host_only, $user, $passwd, $db, $slave_port, $slave_socket);
?>
--INI--
mysqlnd_ms.enable=1
mysqlnd_ms.ini_file=test_mysqlnd_ms_charsets_fail.ini
--FILE--
<?php
	require_once("connect.inc");
	require_once("mysqlnd_ms_lazy.inc");

	if (!($link = my_mysqli_connect("myapp", $user, $passwd, $db, $port, $socket)))
		printf("[001] [%d] %s\n", mysqli_connect_errno(), mysqli_connect_error());

	run_query(2, $link, "SET @myrole='master'", MYSQLND_MS_MASTER_SWITCH);
	run_query(3, $link, "SET @myrole='slave'", MYSQLND_MS_SLAVE_SWITCH);

	/* slave */
	if (!$res = run_query(4, $link, "SELECT @myrole AS _role, @@character_set_connection AS _charset", MYSQLND_MS_LAST_USED_SWITCH))
		printf("[005] [%d] %s\n", $link->errno, $link->error);

	$row = $res->fetch_assoc();
	if ('slave' != $row['_role'])
		printf("[006] Expecting reply from slave not from '%s'\n", $row['_role']);

	$current_charset = $row['_charset'];
	$new_charset = 'pleasenot';

	/* shall be run on *all* configured machines - all masters, all slaves */
	if (!$link->set_charset($new_charset))
		printf("[007] [%d] %s\n", $link->errno, $link->error);

	/* slave */
	if ($res = run_query(8, $link, "SELECT @myrole AS _role, @@character_set_connection AS _charset", MYSQLND_MS_LAST_USED_SWITCH)) {
		printf("[009] Who is speaking?");
		var_dump($res->fetch_assoc());
	}

	if ($link->character_set_name() != $current_charset)
		printf("[010] Expecting charset '%s' got '%s'\n", $current_charset, $link->character_set_name());

	if ($res = run_query(11, $link, "SELECT @myrole AS _role, @@character_set_connection AS _charset", MYSQLND_MS_MASTER_SWITCH)) {
		printf("[012] Who is speaking?");
		var_dump($res->fetch_assoc());
	 }

	if ($link->character_set_name() != $current_charset)
		printf("[01]3 Expecting charset '%s' got '%s'\n", $current_charset, $link->character_set_name());

	print "done!";

?>
--CLEAN--
<?php
	if (!unlink("test_mysqlnd_ms_charsets_fail.ini"))
	  printf("[clean] Cannot unlink ini file 'test_mysqlnd_ms_charsets_fail.ini'.\n");
?>
--EXPECTF--
[007] [%d] %s
[008] [%d] %s
[011] [%d] %s
done!