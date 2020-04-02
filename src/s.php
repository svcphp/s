<?php

class s
{
	static private $_s;
	static private $_old_s;

	static private function current(): Service
	{
		return self::$_s;
	}

	static function init(): Service
	{
		self::$_s = new Service();
		return self::$_s;
	}

	static function call($name, $data)
	{
		return self::current()->call($name, $data);
	}

	static function ok($data, $code = 1, $message = '')
	{
		return self::current()->ok($data, $code, $message);
	}

	static function failed($code = -1, $message = '', $data = null)
	{
		return self::current()->failed($data, $code, $message);
	}

	static function __callStatic($name, $arguments)
	{
		return call_user_func_array([self::$_s, $name], $arguments);
	}

	static function _store()
	{
		self::$_old_s = self::$_s;
	}

	static function _restore()
	{
		self::$_s = self::$_old_s;
		return null;
	}

}
