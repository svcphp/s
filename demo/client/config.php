<?php

$_CONFIG = [
	'SERVICE_APP' => 'client',
	'SERVICE_GROUP_BASE' => str_replace('client/index.php/test', '', "{$_SERVER['REQUEST_SCHEME']}://{$_SERVER['HTTP_HOST']}{$_SERVER['REQUEST_URI']}"),
	'SERVICE_CALL_NAMESERVICE' => 'token2:10',
];
