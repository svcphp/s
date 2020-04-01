<?php

class s
{
	static private $_s = null;
	static private $_old_s = null;

	static function init(): Service
	{
		self::$_s = new Service();
		return self::$_s;
	}

	static function call($name, $data)
	{
		return self::$_s->call($name, $data);
	}

	static function __callStatic($name, $arguments)
	{
		if ($name === '_store') {
			self::$_old_s = self::$_s;
			self::$_s = null;
			return null;
		} else if ($name === '_restore') {
			self::$_s = self::$_old_s;
			self::$_old_s = null;
			return null;
		}
		return call_user_func_array([self::$_s, $name], $arguments);
	}
}
