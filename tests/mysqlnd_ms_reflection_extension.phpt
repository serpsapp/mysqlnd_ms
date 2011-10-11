--TEST--
ReflectionExtension basics to check API
--SKIPIF--
<?php
require_once('skipif.inc');
?>
--FILE--
<?php
	$r = new ReflectionExtension("mysqlnd_ms");

	printf("Name: %s\n", $r->name);

	printf("Version: %s\n", $r->getVersion());
	if ($r->getVersion() != MYSQLND_MS_VERSION) {
		printf("[001] Expecting version '%s' got '%s'\n", MYSQLND_MS_VERSION, $r->getVersion());
	}

	$classes = $r->getClasses();
	if (!empty($classes)) {
		printf("[002] Expecting no class\n");
		asort($classes);
		var_dump($classes);
	}

	$dependencies = $r->getDependencies();
	asort($dependencies);
	printf("Dependencies:\n");
	foreach ($dependencies as $what => $how)
		printf("  %s - %s\n", $what, $how);

	$functions = $r->getFunctions();
	asort($functions);
	printf("Functions:\n");
	foreach ($functions as $func)
		printf("  %s\n", $func->name);

	print "done!";
?>
--EXPECTF--
Name: mysqlnd_ms
Version: 1.1.1-beta
Dependencies:
  json - Required
  standard - Required
  mysqlnd - Required
Functions:
  mysqlnd_ms_get_last_used_connection
  mysqlnd_ms_get_stats
  mysqlnd_ms_match_wild
  mysqlnd_ms_query_is_select
done!