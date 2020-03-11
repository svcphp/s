<?php

// v0.0.3
class s
{
	static private $apis = [];
	static private $authChecker = ['s', 'defaultAuthChecker'];
	static private $requestData = [];
	static private $request = [];
	static private $serveStartTime = 0;
	static private $pdos = null;
	static private $redises = null;
	static private $cryptstr = '?GQ$0K0GgLdO=f+~L68PLm$uhKr4\'=tVVFs7@sK61cj^f?HZ';

	static function call($name, $data)
	{
		global $_CONFIG;
		$names = explode('.', $name, 3);
		if (count($names) !== 3) return null;

		$groupUrl = $_CONFIG['SERVICE_GROUP_' . strtoupper(explode('.', $name)[0])];
		list($token, $timeout) = explode(':', $_CONFIG['SERVICE_CALL_' . strtoupper($names[1])]);
		if (!$timeout) $timeout = $_CONFIG['SERVICE_CALLTIMEOUT'];
		if ($groupUrl) {
			$json_data = json_encode($data);
			$ch = curl_init($groupUrl . $names[1] . '/index.php/' . str_replace('.', '/', $names[2]));
			curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "POST");
			curl_setopt($ch, CURLOPT_POSTFIELDS, $json_data);
			curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, $timeout);
			curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
			curl_setopt($ch, CURLOPT_HTTPHEADER, [
				'Content-Type: application/json',
				'Content-Length: ' . strlen($json_data),
				'X-Real-IP: ' . $_SERVER['HTTP_X_REAL_IP'],
				'X-Request-ID: ' . $_SERVER['HTTP_X_REQUEST_ID'],
				'X-Host: ' . $_SERVER['HTTP_X_HOST'],
				'X-Scheme: ' . $_SERVER['HTTP_X_SCHEME'],
				'X-Client-ID: ' . $_SERVER['HTTP_X_CLIENT_ID'],
				'X-From-App: ' . $_CONFIG['SERVICE_APP'],
				'X-From-Node: ' . $_SERVER['SERVER_ADDR'] . ':' . $_SERVER['SERVER_PORT'],
				'Access-Token: ' . $token,
			]);
			$output = curl_exec($ch);
			curl_close($ch);

			$result = json_decode($output, JSON_UNESCAPED_UNICODE);
			$err = curl_error($ch);
			if ($result === null || $err) {
				self::error('call ' . $name, ['callName' => $name, 'data' => $data, 'error' => $err]);
			} else {
				self::info('call ' . $name, ['callName' => $name, 'data' => $data, 'resultLength' => strlen($output)]);
			}
			return $result;
		}
	}

	static function init()
	{
		self::$serveStartTime = microtime(true);
		set_error_handler(['s', 'errorHandler'], E_ALL);
		register_shutdown_function(['s', 'shutdownHandler']);

		global $_CONFIG;
		if (!isset($_CONFIG['SERVICE_NOLOGHEADERS'])) $_CONFIG['SERVICE_NOLOGHEADERS'] = 'Accept,Accept-Encoding,Accept-Language,Cache-Control,Pragma,Connection,Upgrade-Insecure-Requests';
		$_CONFIG['SERVICE_NOLOGHEADERS'] = explode(',', $_CONFIG['SERVICE_NOLOGHEADERS']);

		foreach ($_ENV as $k => $v) {
			$K = strtoupper($k);
			if (isset($_CONFIG[$K])) {
				if (!is_string($_CONFIG[$K]) && is_string($v)) {
					$_CONFIG[$K] = json_decode($v, JSON_UNESCAPED_UNICODE);
				} else {
					$_CONFIG[$K] = $v;
				}
			}
		}

		if (!$_CONFIG['SERVICE_CALLTIMEOUT']) {
			$_CONFIG['SERVICE_CALLTIMEOUT'] = 60;
		}

		if (!$_CONFIG['SERVICE_SESSIONKEY']) {
			$_CONFIG['SERVICE_SESSIONKEY'] = 'sessionId';
		}

		if (!$_CONFIG['SERVICE_CLIENTKEY']) {
			$_CONFIG['SERVICE_CLIENTKEY'] = 'clientId';
		}

		if (!$_CONFIG['LOG_FILE']) {
			$_CONFIG['LOG_FILE'] = 'php://stderr';
		}

		if (!isset($_CONFIG['LOG_SENSITIVE'])) $_CONFIG['LOG_SENSITIVE'] = 'phone,password,secure,token,accessToken';
		$_CONFIG['LOG_SENSITIVE'] = explode(',', strtoupper($_CONFIG['LOG_SENSITIVE']));

		if (!$_SERVER['HTTP_X_REAL_IP']) $_SERVER['HTTP_X_REAL_IP'] = $_SERVER['REMOTE_ADDR'];
		if (!$_SERVER['HTTP_X_REQUEST_ID']) $_SERVER['HTTP_X_REQUEST_ID'] = base_convert($_SERVER['REQUEST_TIME'] * 1000 % 31536000000, 10, 36) . '-' . base_convert(rand(1000000000, 9999999999), 10, 36);
		if (!$_SERVER['HTTP_X_HOST']) $_SERVER['HTTP_X_HOST'] = $_SERVER['HTTP_HOST'];
		if (!$_SERVER['HTTP_X_SCHEME']) $_SERVER['HTTP_X_SCHEME'] = $_SERVER['REQUEST_SCHEME'];
		if (!$_SERVER['HTTP_X_SESSION_ID']) $_SERVER['HTTP_X_SESSION_ID'] = $_SERVER['HTTP_' . strtoupper($_CONFIG['SERVICE_SESSIONKEY'])];
		if (!$_SERVER['HTTP_X_CLIENT_ID']) $_SERVER['HTTP_X_CLIENT_ID'] = $_SERVER['HTTP_' . strtoupper($_CONFIG['SERVICE_CLIENTKEY'])];
	}

	static function serve()
	{
		if (!$_SERVER['HTTP_X_SESSION_ID']) $_SERVER['HTTP_X_SESSION_ID'] = session_id();

		$requestData = $_POST;
		if (!$requestData && $_SERVER['REQUEST_METHOD'] !== 'GET') {
			$post_data = file_get_contents('php://input');
			if (strlen($post_data) > 0 && (strstr($_SERVER['CONTENT_TYPE'], 'json') || $post_data[0] === '{')) {
				$requestData = json_decode($post_data, JSON_UNESCAPED_UNICODE);
			}
		}
		self::$requestData = &$requestData;

		$responseData = [];

		// 查找接口
		$apiName = str_replace('/', '.', substr($_SERVER['PATH_INFO'], 1));
		self::$request = self::$apis[$apiName];

		if (!self::$request) {
			return self::output(404, self::failed(-404, 'api not registered'));
		}

		$names = explode('.', $apiName);
		$name_num = count($names);
		$method = $names[$name_num - 1];
		$class = '';
		if ($name_num > 1) {
			$class = $names[$name_num - 2];
		}
		$path = '';
		if ($name_num > 2) {
			$path = join('/', array_slice($names, 0, $name_num - 2));
		}

		if ($class && !class_exists($class)) {
			if ($path) {
				include "$path/$class.php";
			} else {
				include "$class.php";
			}
		}

		if ($class) {
			if (!class_exists($class)) {
				self::error("api class not found", ['api' => $apiName, 'file' => "$path/$class.php", 'class' => $class, 'method' => $method]);
				return self::output(404, self::failed(-404, 'api class not found'));
			}
			if (!method_exists($class, $method)) {
				self::error("api method not found", ['api' => $apiName, 'file' => "$path/$class.php", 'class' => $class, 'method' => $method]);
				return self::output(404, self::failed(-404, 'api method not found'));
			}
			$call_name = [$class, $method];
		} else {
			if (!function_exists($method)) {
				self::error("api function not found", ['api' => $apiName]);
				return self::output(404, self::failed(-404, 'api function not found'));
			}
			$call_name = $method;
		}

		// 验证权限
		if (self::$request['authLevel'] > 0) {
			if (!call_user_func(self::$authChecker, self::$request['authLevel'], $apiName, $requestData)) {
				return self::output(403, self::failed(-403, 'auth failed'));
			}
		}

		// 调用
		$responseData = call_user_func($call_name, $requestData);
		return self::output(200, $responseData);
	}

	static function output($responseCode, $responseData)
	{
		if ($responseCode !== 200) {
			http_response_code($responseCode);
		}

		$outData = json_encode($responseData);
		if ($outData === '[]') $outData = '{}';

		self::logRequest($responseData, strlen($outData));
		echo $outData;
		return null;
	}

	static function setAuthChecker($authChecker)
	{
		self::$authChecker = $authChecker;
	}

	static function register($name, $authLevel = 0, $priority = 5)
	{
		self::$apis[$name] = [
			'authLevel' => $authLevel,
			'priority' => $priority,
		];
	}

	static function log($data, $extra = null)
	{
		global $_CONFIG, $_TRACE_ID;
		$mtime = microtime(true);
		if (!$_TRACE_ID) $_TRACE_ID = base_convert($_SERVER['REQUEST_TIME'] * 1000 % 31536000000, 10, 36) . '-' . base_convert(rand(1000000000, 9999999999), 10, 36);
		$data['logTime'] = $mtime;
		$data['traceId'] = $_TRACE_ID;
		if ($extra) {
			if (is_array($extra)) {
				foreach ($extra as $k => $v) {
					if (in_array(strtoupper($k), $_CONFIG['LOG_SENSITIVE'])) $extra[$k] = self::getSensitiveStr($v);
					if (is_array($v) && !isset($v[0])) {
						foreach ($v as $k2 => $v2) {
							if (in_array(strtoupper($k2), $_CONFIG['LOG_SENSITIVE'])) $extra[$k][$k2] = self::getSensitiveStr($v2);
						}
					}
				}
			}
			$data['extra'] = $extra;
		}
		file_put_contents($_CONFIG['LOG_FILE'], sprintf("%s%06s %s\n", date("Y/m/d H:i:s."), $mtime * 1000000 % 10000, json_encode($data)));
	}

	static function logRequest(&$responseData, $responseDataLength)
	{
		global $_CONFIG;
		$node = $_SERVER['SERVER_ADDR'] . ':' . $_SERVER['SERVER_PORT'];

		$log_in_headers = [];
		foreach (getallheaders() as $k => $v) {
			if (in_array($k, $_CONFIG['SERVICE_NOLOGHEADERS'])) continue;
			if (in_array(strtoupper(str_replace('-', '', $k)), $_CONFIG['LOG_SENSITIVE'])) $v = self::getSensitiveStr($v);
			$log_in_headers[$k] = $v;
		}

		$log_out_headers = [];
		foreach (headers_list() as $a) {
			list($k, $v) = explode(': ', $a, 2);
			if (in_array($k, $_CONFIG['SERVICE_NOLOGHEADERS'])) continue;
			if (in_array(strtoupper(str_replace('-', '', $k)), $_CONFIG['LOG_SENSITIVE'])) $v = self::getSensitiveStr($v);
			$log_out_headers[$k] = $v;
		}

		if (is_array(self::$requestData)) {
			$logRequestData = [];
			foreach (self::$requestData as $k => $v) {
				if (is_array($v) && isset($v[0])) {
					$v = [$v[0]];
				}
				if (in_array(strtoupper($k), $_CONFIG['LOG_SENSITIVE'])) $v = self::getSensitiveStr($v);
				if (is_array($v) && !isset($v[0])) {
					foreach ($v as $k2 => $v2) {
						if (in_array(strtoupper($k2), $_CONFIG['LOG_SENSITIVE'])) $v[$k2] = self::getSensitiveStr($v2);
					}
				}
				$logRequestData[$k] = $v;
			}
		} else {
			$logRequestData = self::$requestData;
		}

		if (is_array($responseData)) {
			$logResponseData = [];
			foreach ($responseData as $k => $v) {
				if (is_array($v) && isset($v[0])) {
					$v = [$v[0]];
				}
				if (in_array(strtoupper($k), $_CONFIG['LOG_SENSITIVE'])) $v = self::getSensitiveStr($v);
				if (is_array($v) && !isset($v[0])) {
					foreach ($v as $k2 => $v2) {
						if (in_array(strtoupper($k2), $_CONFIG['LOG_SENSITIVE'])) $v[$k2] = self::getSensitiveStr($v2);
					}
				}
				$logResponseData[$k] = $v;
			}
		} else {
			$logResponseData = $responseData;
		}

		$now_time = microtime(true);
		self::log([
			'logType' => 'request',
			'serverId' => $node,
			'app' => $_CONFIG['SERVICE_APP'],
			'node' => $node,
			'clientIp' => $_SERVER['HTTP_X_REAL_IP'],
			'fromApp' => $_SERVER['HTTP_X_FROM_APP'],
			'fromNode' => $_SERVER['HTTP_X_FROM_NODE'],
			'clientId' => $_SERVER['HTTP_X_CLIENT_ID'],
			'sessionId' => $_SERVER['HTTP_X_SESSION_ID'],
			'requestId' => $_SERVER['HTTP_X_REQUEST_ID'],
			'host' => $_SERVER['HTTP_X_HOST'],
			'proto' => substr($_SERVER['SERVER_PROTOCOL'], 5),
			'authLevel' => self::$request['authLevel'],
			'priority' => self::$request['priority'],
			'method' => $_SERVER['REQUEST_METHOD'],
			'path' => $_SERVER['PATH_INFO'],
			'requestHeaders' => $log_in_headers,
			'requestData' => $logRequestData,
			'usedTime' => intval(($now_time - self::$serveStartTime) * 1000000000) / 1000000,
			'fullUsedTime' => intval(($now_time - $_SERVER['REQUEST_TIME']) * 1000000000) / 1000000,
			'responseCode' => http_response_code(),
			'responseHeaders' => $log_out_headers,
			'responseDataLength' => $responseDataLength,
			'responseData' => $logResponseData,
		]);
	}

	static function getSensitiveStr($str)
	{
		if (!is_string($str)) $str = json_encode($str);
		$len = strlen($str);
		if ($len >= 11) {
			return substr($str, 0, 3) . '****' . substr($str, -4);
		} else if ($len >= 6) {
			return substr($str, 0, 2) . '**' . substr($str, -2);
		} else {
			return '**';
		}
	}

	static function info($msg, $extra = null)
	{
		self::log([
			'logType' => 'info',
			'info' => $msg,
		], $extra);
	}

	static function error($msg, $extra = null)
	{
		self::log([
			'logType' => 'error',
			'error' => $msg,
			'callStacks' => self::getCallStacks(),
		], $extra);
	}

	static function warning($msg, $extra = null)
	{
		self::log([
			'logType' => 'warning',
			'warning' => $msg,
			'callStacks' => self::getCallStacks(),
		], $extra);
	}

	static function debug($msg, $extra = null)
	{
		self::log([
			'logType' => 'debug',
			'debug' => $msg,
			'callStacks' => self::getCallStacks(),
		], $extra);
	}

	static protected function getCallStacks()
	{
		ob_start();
		debug_print_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS);
		$trace = ob_get_contents();
		ob_end_clean();
		$callStacks = explode("\n", trim($trace));
		array_shift($callStacks);
		array_shift($callStacks);
		return $callStacks;
	}


	static function errorHandler($errno, $errstr, $errfile, $errline, $errcontext)
	{
		if ($errno == E_DEPRECATED || $errno == E_USER_DEPRECATED || $errno == E_STRICT ||
			($errno == E_NOTICE && (strstr($errstr, 'ndefined') || strstr($errstr, 'Uninitialized')))
		) return true;

		$info = [
			'errno' => $errno,
			'errfile' => $errfile,
			'errline' => $errline,
			'errcontext' => $errcontext,
		];
		if ($errno == E_ERROR || $errno == E_USER_ERROR) {
			self::error($errstr, $info);
		} else if ($errno == E_WARNING || $errno == E_USER_WARNING) {
			self::warning($errstr, $info);
		}
		return true;
	}

	static function shutdownHandler()
	{
		if ($error = error_get_last()) {
			$errno = $error['type'];
//            if ($errno == E_ERROR || $errno == E_WARNING || $errno == E_USER_ERROR || $errno == E_USER_WARNING) {
			if ($errno == E_ERROR || $errno == E_USER_ERROR) {
				self::error('500 Internal Server Error', $error);
				http_response_code(500);
				$result = [];
				self::logRequest($result, 2);
				echo '{}';
			}
		}
	}

	static function defaultAuthChecker($authLevel, $apiName, $requestData)
	{
		global $_CONFIG;
		$settedAuthLevel = $_CONFIG['SERVICE_ACCESSTOKENS'][$_SERVER['HTTP_ACCESS_TOKEN']];
		return $settedAuthLevel && $settedAuthLevel >= $authLevel;
	}

	static function ok($data, $code = 1, $message = '')
	{
		return [
			'code' => $code,
			'message' => $message,
			'data' => $data
		];
	}

	static function failed($code = -1, $message = '', $data = null)
	{
		return [
			'code' => $code,
			'message' => $message,
			'data' => $data
		];
	}

	static function getDB($name = '')
	{
		if (self::$pdos[$name . '_']) return self::$pdos[$name . '_'];
		global $_CONFIG;
		$prefix = 'DB_';
		if ($name !== '') $prefix = 'DB_' . strtoupper($name) . '_';
		if (!$_CONFIG[$prefix . 'OPTIONS']) $_CONFIG[$prefix . 'OPTIONS'] = [
			PDO::ATTR_TIMEOUT => 3,
			PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES 'UTF8'",
			PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
			PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
			PDO::ATTR_EMULATE_PREPARES => false,
			PDO::ATTR_STRINGIFY_FETCHES => false,
			PDO::ATTR_PERSISTENT => false,
		];
		$pdo = new PDO($_CONFIG[$prefix . 'DSN'], $_CONFIG[$prefix . 'USER'], self::decryptPassword($_CONFIG[$prefix . 'PASSWORD']), $_CONFIG[$prefix . 'OPTIONS']);
		self::$pdos[$name . '_'] = $pdo;
		return $pdo;
	}

	static function getRedis($name = '')
	{
		if (self::$redises[$name . '_']) return self::$redises[$name . '_'];
		global $_CONFIG;
		$prefix = 'REDIS_';
		if ($name !== '') $prefix = 'REDIS_' . strtoupper($name) . '_';
		list($host, $port, $n) = explode(':', $_CONFIG[$prefix . 'HOST']);
		if (!$host) $host = '127.0.0.1';
		if (!$port) $port = 6379;
		if (!$n || $n < 0 || $n > 15) $n = 0;
		$redis = new Redis();
		$redis->connect($host, $port);
		if ($_CONFIG[$prefix . 'PASSWORD']) {
			$redis->auth(self::decryptPassword($_CONFIG[$prefix . 'PASSWORD']));
		}
		if ($n) {
			$redis->select($n);
		}
		return $redis;
	}

	static function decryptPassword($str)
	{
		$decrypted = @mcrypt_decrypt(MCRYPT_RIJNDAEL_128, substr(self::$cryptstr, 0, 32), base64_decode($str), MCRYPT_MODE_CBC, substr(self::$cryptstr, 32));
		$pwd = substr($decrypted, 0, -ord($decrypted[strlen($decrypted) - 1]));
		if (!$pwd) $pwd = $str;
		return $pwd;
	}
}
