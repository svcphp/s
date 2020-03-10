<?php

include '../../s.php';
include 'config.php';
if (file_exists('user_config.php')) include 'user_config.php';
s::init();

include 'client.php';

s::register('test', 'test');
s::serve();
