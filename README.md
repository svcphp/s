# a simple php framework for micro service

## controller demo

##### index.php

```php
<?php
require_once 'vendor/autoload.php';
include 'config.php';

$s = s::init();
$s->register('account.login');
$s->serve();
```

##### config.php

```php
<?php

$_CONFIG = [
	'SERVICE_APP' => 'usergateway',
	'SERVICE_CALL_USER' => 'token123abc',
];

if (file_exists('user_config.php')) {
	/** @noinspection PhpIncludeInspection */
	include 'user_config.php';
}
```

##### account.php

```php
<?php

class account
{
	static function login($data)
	{
		$r = s::call('services.user.account.login', ['name' => $data['name'], 'password' => $data['password']]);
		return s::ok(['logined' => $r['data']['logined'] === true]);
	}
}
```


## user service demo

##### index.php

```php
<?php
require_once 'vendor/autoload.php';
include 'config.php';

$s = s::init();
$s->register('account.login', 1);
$s->serve();
```

##### config.php

```php
<?php

$_CONFIG = [
	'SERVICE_APP' => 'userservice',
	'SERVICE_ACCESSTOKENS' => ['token123abc' => 1, 'token456' => 2],
];

if (file_exists('user_config.php')) {
	/** @noinspection PhpIncludeInspection */
	include 'user_config.php';
}
```

##### account.php

```php
<?php

class account
{
	static function login($data)
	{
        $logined = $data['name'] === 'admin' && $data['password'] === 'admin';
		return s::ok(['logined' => $logined]);
	}
}
```
