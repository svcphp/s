<?php

class cc
{
	static function test($data)
	{
		$r = s::call('base.nameservice.setName', ['name' => 'Tom']);
		$r = s::call('base.nameservice.getName', []);
		return s::ok(['name' => $r['data']['name']]);
	}
}