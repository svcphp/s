<?php

$_CONFIG = [
	'SERVICE_APP' => 'client',
	'SERVICE_GROUP_BASE' => explode('client/index.php', "{$_SERVER['REQUEST_SCHEME']}://{$_SERVER['HTTP_HOST']}{$_SERVER['REQUEST_URI']}")[0],
	'SERVICE_CALL_NAMESERVICE' => 'token2:10',
];
