<?php

include '../../s.php';
include 'config.php';
if (file_exists('user_config.php')) include 'user_config.php';
s::init();

include 'client.php';

s::register('aa.bb.cc.test');
s::register('cc.test');
s::register('test');
s::serve();
