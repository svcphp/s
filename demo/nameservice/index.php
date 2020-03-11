<?php

include '../../s.php';
include 'config.php';
if (file_exists('user_config.php')) include 'user_config.php';
s::init();

include 'name.php';

s::register('getName', 1);
s::register('setName', 2);

s::serve();
