--TEST--
SQL hints LAST_USED called before any server has been selected, pick = random
--SKIPIF--
<?php
require_once('skipif.inc');
require_once("connect.inc");

$settings = array(
	"myapp" => array(
		'master' => array($master_host),
		'slave' => array($slave_host),
		'pick' => array("random"),
	),
);
if ($error = create_config("test_mysqlnd_ms_last_used_random.ini", $settings))
  die(sprintf("SKIP %s\n", $error));
?>
--INI--
mysqlnd_ms.enable=1
mysqlnd_ms.ini_file=test_mysqlnd_ms_last_used_random.ini
--FILE--
<?php
	require_once("connect.inc");
	require_once("mysqlnd_ms_lazy.inc");

	if (!($link = my_mysqli_connect("myapp", $user, $passwd, $db, $port, $socket)))
		printf("[001] [%d] %s\n", mysqli_connect_errno(), mysqli_connect_error());

	if (!$link->query(sprintf("/*%s*/SELECT 1", MYSQLND_MS_LAST_USED_SWITCH)))
		printf("[002] [%d][%s] %s\n", $link->errno, $link->sqlstate, $link->error);

	print "done!";
?>
--CLEAN--
<?php
	if (!unlink("test_mysqlnd_ms_last_used_random.ini"))
	  printf("[clean] Cannot unlink ini file 'test_mysqlnd_ms_last_used_random.ini'.\n");
?>
--EXPECTF--
Warning: mysqli::query(): (mysqlnd_ms) Last used SQL hint cannot be used because last used connection has not been set yet. Statement will fail in %s on line %d

Warning: mysqli::query(): (mysqlnd_ms) No connection selected by the last filter in %s on line %d
[002] [2000][HY000] (mysqlnd_ms) No connection selected by the last filter
done!