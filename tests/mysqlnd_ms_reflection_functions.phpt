--TEST--
ReflectionFunction to check API
--SKIPIF--
<?php
require_once('skipif.inc');
?>
--FILE--
<?php
	$r = new ReflectionExtension("mysqlnd_ms");

	$functions = $r->getFunctions();
	asort($functions);
	printf("Functions:\n");
	foreach ($functions as $func) {
		printf("  %s\n", $func->name);
		$rf = new ReflectionFunction($func->name);
		printf("    Deprecated: %s\n", $rf->isDeprecated() ? "yes" : "no");
		printf("    Accepted parameters: %d\n", $rf->getNumberOfParameters());
		printf("    Required parameters: %d\n", $rf->getNumberOfRequiredParameters());
		foreach( $rf->getParameters() as $param ) {
			printf("      %s\n", $param);
		}
	}

	print "done!";
?>
--EXPECTF--
Functions:
  mysqlnd_ms_get_stats
    Deprecated: no
    Accepted parameters: 0
    Required parameters: 0
  mysqlnd_ms_match_wild
    Deprecated: no
    Accepted parameters: 2
    Required parameters: 2
      Parameter #0 [ <required> $haystack ]
      Parameter #1 [ <required> $wild ]
  mysqlnd_ms_query_is_select
    Deprecated: no
    Accepted parameters: 1
    Required parameters: 1
      Parameter #0 [ <required> $query ]
done!