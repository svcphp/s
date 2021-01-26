<?php

class Service
{
	private $config = [];
	private $apis = [];
	private $authChecker = null;
	private $requestData = [];
	private $request = [];
	private $serveStartTime = 0;
	private $pdos = null;
	private $redises = null;
	private $encrypt = '';
	private $curlPool = null;
	static private $isFirst = true;

	function call($name, $data)
	{
		return $this->multiCall([[$name, $data]])[0];
	}

	function multiCall($requests)
	{
		$curl_num = 0;
		$fast_num = 0;
		$results = [];
		foreach ($requests as $k => $v) {
			list($name, $data) = $v;
			$names = explode('.', $name, 2);
			if (count($names) !== 2) return null;
			list($service_name, $path_name) = $names;

			$serviceRoot = $this->config['SERVICE_' . strtoupper($service_name)];
			if (!$serviceRoot) {
				$serviceRoot = '../';
			}
			list($token, $timeout) = explode(':', $this->config['SERVICE_CALL_' . strtoupper($service_name)]);

//			$serviceRoot = $_SERVER['REQUEST_SCHEME'] . '://' . $_SERVER['HTTP_HOST'] . preg_split('#\\w+/index.php#', $_SERVER['REQUEST_URI'])[0];
			if (strtolower(substr($serviceRoot, 0, 4)) != 'http') {
				$requests[$k][] = 'fast';
				$local_path = $serviceRoot . $service_name;
				$requests[$k][] = $local_path;
				$requests[$k][] = '/' . str_replace('.', '/', $path_name);
				$requests[$k][] = $token;
				$fast_num++;
			} else {
				if (!$timeout) $timeout = $this->config['SERVICE_CALL_TIMEOUT'];

				$requests[$k][] = 'curl';
				$curl_num++;
				$url = $serviceRoot . $service_name . '/index.php/' . str_replace('.', '/', $path_name);
				$requests[$k][] = $url;

				$json_data = json_encode($data);
				$ch = curl_init();
				curl_setopt($ch, CURLOPT_URL, $url);
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
					'X-From-App: ' . $this->config['SERVICE_APP'],
					'X-From-Node: ' . $_SERVER['SERVER_ADDR'] . ':' . $_SERVER['SERVER_PORT'],
					'Access-Token: ' . $token,
				]);
				$requests[$k][] = $ch;
				$requests[$k][] = $token;
			}
			$results[] = null;
		}

		if ($fast_num > 0) {
			foreach ($requests as $k => $v) {
				list(, $data, $type, $local_path, $path_info, $token) = $v;
				if ($type === 'fast' && file_exists($local_path) && file_exists($local_path . '/index.php')) {
					$old_path = getcwd();
					chdir($local_path);

					global $_CONFIG;
					$_CONFIG = [];
					$old_server = $_SERVER;
					$_SERVER['REQUEST_METHOD'] = 'POST';
					$_POST = $data;
					$_SERVER['PATH_INFO'] = $path_info;
					$_SERVER['HTTP_X_FROM_APP'] = $this->config['SERVICE_APP'];
					$_SERVER['HTTP_X_FROM_NODE'] = $_SERVER['SERVER_ADDR'] . ':' . $_SERVER['SERVER_PORT'];
					$_SERVER['HTTP_ACCESS_TOKEN'] = $token;

					s::_store();
					ob_start();
					/** @noinspection PhpIncludeInspection */
					include 'index.php';
					$output = ob_get_contents();
					ob_end_clean();
					s::_restore();
					restore_error_handler();

					$_SERVER = $old_server;
					chdir($old_path);
					$results[$k] = json_decode($output, JSON_UNESCAPED_UNICODE);
					if($output && !$results[$k]){
                        $this->error('call ' . $name, ['callName' => $name, 'url' => $url, 'data' => $data, 'error' => json_last_error_msg()]);
                        $results[$k] = $output;
					}
				}
			}
		}

		if ($curl_num > 0) {
			if ($this->curlPool === null) {
				$this->curlPool = curl_multi_init();
			}

			foreach ($requests as $k => $v) {
				list(, , $type, , $ch) = $v;
				if ($type === 'curl') {
					curl_multi_add_handle($this->curlPool, $ch);
				}
			}

			$running = null;
			do {
				curl_multi_exec($this->curlPool, $running);
				curl_multi_select($this->curlPool);
			} while ($running > 0);

			foreach ($requests as $k => $v) {
				list($name, $data, , $url, $ch) = $v;
				$output = curl_multi_getcontent($ch);
				$result = json_decode($output, JSON_UNESCAPED_UNICODE);
				$err = curl_error($ch);
				if ($result === null || $err) {
					$this->error('call ' . $name, ['callName' => $name, 'url' => $url, 'data' => $data, 'error' => $err]);
				} else {
					$this->info('call ' . $name, ['callName' => $name, 'url' => $url, 'data' => $data, 'resultLength' => strlen($output)]);
				}
				$results[$k] = $result;
				curl_multi_remove_handle($this->curlPool, $ch);
			}
		}

		return $results;
	}

	function __construct($conf = null)
	{
		if ($conf === null) {
			global $_CONFIG;
			$this->config = $_CONFIG;
		} else {
			$this->config = $conf;
		}
		$this->serveStartTime = microtime(true);
		set_error_handler([$this, 'errorHandler'], E_ALL);
		if (self::$isFirst) {
			register_shutdown_function([$this, 'shutdownHandler']);
		}

		if (!isset($this->config['SERVICE_NOLOGHEADERS'])) $this->config['SERVICE_NOLOGHEADERS'] = 'Accept,Accept-Encoding,Accept-Language,Cache-Control,Pragma,Connection,Upgrade-Insecure-Requests';
		$this->config['SERVICE_NOLOGHEADERS'] = explode(',', $this->config['SERVICE_NOLOGHEADERS']);

		foreach ($_ENV as $k => $v) {
			$K = strtoupper($k);
			if (isset($this->config[$K])) {
				if (!is_string($this->config[$K]) && is_string($v)) {
					$this->config[$K] = json_decode($v, JSON_UNESCAPED_UNICODE);
				} else {
					$this->config[$K] = $v;
				}
			}
		}

		if (!$this->config['SERVICE_CALL_TIMEOUT']) {
			$this->config['SERVICE_CALL_TIMEOUT'] = 60;
		}

		if (!$this->config['LOG_FILE']) {
			$this->config['LOG_FILE'] = 'php://stderr';
		}

		if (!isset($this->config['LOG_SENSITIVE'])) $this->config['LOG_SENSITIVE'] = 'phone,password,secure,token,accessToken';
		$this->config['LOG_SENSITIVE'] = explode(',', strtoupper($this->config['LOG_SENSITIVE']));

		$this->encrypt = '?GQ$0K0GgLdO=f+~L68PLm$uhKr4\'=tVVFs7@sK61cj^f?HZ';
		if ($this->config['SERVICE_ENCRYPT']) {
			$encrypt = base64_decode($this->decryptPassword($this->config['SERVICE_ENCRYPT']));
			$this->encrypt = substr($encrypt, 2, 32) . substr($encrypt, 45, 16);
			$this->config['SERVICE_ENCRYPT'] = '';
		}

		$this->authChecker = [$this, 'defaultAuthChecker'];

		header('X-Powered-By: s');
		header('Server: s');

		// 支持使用Redis作为SESSION存储
		if ($this->config['REDIS_SESSION_HOST']) {
			list($redis_host, $redis_port, $redis_database) = explode(':', $this->config["REDIS_SESSION_HOST"]);
			if (!$redis_port) $redis_port = 6379;
			if (!$redis_database) $redis_database = 0;
			$redis_password = $this->config["REDIS_SESSION_PASSWORD"];
			if ($redis_password) $redis_password = $this->decryptPassword($redis_password);
			ini_set('session.save_handler', 'redis');
			ini_set('session.save_path', "tcp://$redis_host:$redis_port?auth=$redis_password&database=$redis_database");
			if ($this->config['SERVICE_SESSION_KEY']) {
				$session_id = $this->getHeader($this->config['SERVICE_SESSION_KEY']);
				if (!$session_id) {
					$session_id = base_convert(rand(10000000, 99999999), 10, 35) . '-' . base_convert($_SERVER['REQUEST_TIME'] * 1000 % 31536000000, 10, 36) . '-' . base_convert(rand(1000000000, 9999999999), 10, 36);
					header("{$this->config['SERVICE_SESSION_KEY']}: $session_id");
				}
				ini_set('session.use_cookies', 0);
				if ($this->config['REDIS_SESSION_TTL']) {
					ini_set('session.gc_maxlifetime', $this->config['REDIS_SESSION_TTL']);
				}
				session_id($session_id);
			}
			session_start();
		}

		if (!$_SERVER['HTTP_X_CLIENT_ID'] && $this->config['SERVICE_CLIENT_KEY']) {
			$_SERVER['HTTP_X_CLIENT_ID'] = $this->getHeader($this->config['SERVICE_CLIENT_KEY']);
			if (!$_SERVER['HTTP_X_CLIENT_ID']) {
				$_SERVER['HTTP_X_CLIENT_ID'] = base_convert(rand(10000000, 99999999), 10, 35) . '-' . base_convert($_SERVER['REQUEST_TIME'] * 1000 % 31536000000, 10, 36) . '-' . base_convert(rand(1000000000, 9999999999), 10, 36);
				setcookie($this->config['SERVICE_CLIENT_KEY'], $_SERVER['HTTP_X_CLIENT_ID'], 0, '/');
			}
		}

		if (!$_SERVER['HTTP_X_REAL_IP']) $_SERVER['HTTP_X_REAL_IP'] = $_SERVER['REMOTE_ADDR'];
		if (!$_SERVER['HTTP_X_REQUEST_ID']) $_SERVER['HTTP_X_REQUEST_ID'] = base_convert($_SERVER['REQUEST_TIME'] * 1000 % 31536000000, 10, 36) . '-' . base_convert(rand(1000000000, 9999999999), 10, 36);
		if (!$_SERVER['HTTP_X_HOST']) $_SERVER['HTTP_X_HOST'] = $_SERVER['HTTP_HOST'];
		if (!$_SERVER['HTTP_X_SCHEME']) $_SERVER['HTTP_X_SCHEME'] = $_SERVER['REQUEST_SCHEME'];
		if (!$_SERVER['HTTP_X_SESSION_ID']) $_SERVER['HTTP_X_SESSION_ID'] = $this->getHeader($this->config['SERVICE_SESSION_KEY']);

		self::$isFirst = false;
	}

	function getHeader($key)
	{
		return $_SERVER['HTTP_' . str_replace('-', '_', strtoupper($key))];
	}

	function serve()
	{
		if (!$_SERVER['HTTP_X_SESSION_ID']) $_SERVER['HTTP_X_SESSION_ID'] = session_id();
		$this->requestData = $_POST;
		if (!$this->requestData && $_SERVER['REQUEST_METHOD'] !== 'GET') {
			$post_data = file_get_contents('php://input');
			if (strlen($post_data) > 0 && (strstr($_SERVER['CONTENT_TYPE'], 'json') || $post_data[0] === '{')) {
				$this->requestData = json_decode($post_data, JSON_UNESCAPED_UNICODE);
			}
		}

		// 查找接口
		$apiName = str_replace('/', '.', substr($_SERVER['PATH_INFO'], 1));
		$this->request = $this->apis[$apiName];

		if (!$this->request) {
			return $this->output(404, $this->failed(-404, 'api not registered'));
		}

		$names = explode('.', $apiName);
		$name_num = count($names);
		$method = $names[$name_num - 1];
		$classFileName = '';
		$className = '';
		if ($name_num > 1) {
			$classFileName = $names[$name_num - 2];
			$className = $this->config['SERVICE_APP'].'_'.$names[$name_num - 2];
		}
		$path = '';
		if ($name_num > 2) {
			$path = join('/', array_slice($names, 0, $name_num - 2));
		}

		if ($className && !class_exists($className)) {
			if ($path) {
				/** @noinspection PhpIncludeInspection */
				include "$path/$classFileName.php";
			} else {
				include "$classFileName.php";
			}
		}

		if ($className) {
			if (!class_exists($className)) {
				$this->error("api class not found", ['api' => $apiName, 'file' => "$path/$classFileName.php", 'class' => $className, 'method' => $method]);
				return $this->output(404, $this->failed(-404, 'api class not found'));
			}
			if (!method_exists($className, $method)) {
				$this->error("api method not found", ['api' => $apiName, 'file' => "$path/$classFileName.php", 'class' => $className, 'method' => $method]);
				return $this->output(404, $this->failed(-404, 'api method not found'));
			}
			$call_name = [$className, $method];
		} else {
			if (!function_exists($method)) {
				$this->error("api function not found", ['api' => $apiName]);
				return $this->output(404, $this->failed(-404, 'api function not found'));
			}
			$call_name = $method;
		}

		// 验证权限
		if ($this->request['authLevel'] > 0) {
			if (!call_user_func($this->authChecker, $this->request['authLevel'], $apiName, $this->requestData)) {
				return $this->output(403, $this->failed(-403, 'auth failed'));
			}
		}

		// 调用
		$responseData = call_user_func($call_name, $this->requestData);
		return $this->output(200, $responseData);
	}

	function output($responseCode, $responseData)
	{
		if ($responseCode !== 200) {
			http_response_code($responseCode);
		}

		$outData = json_encode($responseData);
		if ($outData === '[]') $outData = '{}';

		$this->logRequest($responseData, strlen($outData));
		echo $outData;
		return null;
	}

	function setAuthChecker($authChecker)
	{
		$this->authChecker = $authChecker;
	}

	function register($name, $authLevel = 0, $priority = 5)
	{
		$this->apis[$name] = [
			'authLevel' => $authLevel,
			'priority' => $priority,
		];
	}

	function log($data, $extra = null)
	{
		global $_TRACE_ID;
		$mtime = microtime(true);
		if (!$_TRACE_ID) $_TRACE_ID = base_convert($_SERVER['REQUEST_TIME'] * 1000 % 31536000000, 10, 36) . '-' . base_convert(rand(1000000000, 9999999999), 10, 36);
		$data['logTime'] = $mtime;
		$data['traceId'] = $_TRACE_ID;
		if ($extra) {
			$data['extra'] = $this->fixSensitive($extra);
		}
		file_put_contents($this->config['LOG_FILE'], sprintf("%s%06s %s\n", date("Y/m/d H:i:s."), $mtime * 1000000 % 10000, json_encode($data)), FILE_APPEND);
	}

	function logRequest(&$responseData, $responseDataLength)
	{
		$node = $_SERVER['SERVER_ADDR'] . ':' . $_SERVER['SERVER_PORT'];

		$log_in_headers = [];
		foreach ($_SERVER as $k => $v) {
			if (substr($k, 0, 5) == 'HTTP_') {
				$k = str_replace(' ', '-', ucwords(strtolower(str_replace('_', ' ', substr($k, 5)))));
				if (in_array($k, ['X-Real-Ip', 'X-Request-Id', 'X-Host', 'X-Scheme', 'X-Session-Id', 'X-Client-Id', 'X-From-App', 'X-From-Node'])) continue;
				if (in_array($k, $this->config['SERVICE_NOLOGHEADERS'])) continue;
				if (in_array(strtoupper(str_replace('-', '', $k)), $this->config['LOG_SENSITIVE'])) $v = $this->getSensitiveStr($v);
				$log_in_headers[$k] = $v;
			}
		}

		$log_out_headers = [];
		foreach (headers_list() as $a) {
			list($k, $v) = explode(': ', $a, 2);
			if (in_array($k, $this->config['SERVICE_NOLOGHEADERS'])) continue;
			if (in_array(strtoupper(str_replace('-', '', $k)), $this->config['LOG_SENSITIVE'])) $v = $this->getSensitiveStr($v);
			$log_out_headers[$k] = $v;
		}

		$logRequestData = $this->fixSensitive($this->requestData);
		$logResponseData = $this->fixSensitive($responseData);

		$now_time = microtime(true);
		$this->log([
			'logType' => 'request',
			'serverId' => $node,
			'app' => $this->config['SERVICE_APP'],
			'node' => $node,
			'clientIp' => $_SERVER['HTTP_X_REAL_IP'],
			'fromApp' => $_SERVER['HTTP_X_FROM_APP'],
			'fromNode' => $_SERVER['HTTP_X_FROM_NODE'],
			'clientId' => $_SERVER['HTTP_X_CLIENT_ID'],
			'sessionId' => $_SERVER['HTTP_X_SESSION_ID'],
			'requestId' => $_SERVER['HTTP_X_REQUEST_ID'],
			'host' => $_SERVER['HTTP_X_HOST'],
			'proto' => substr($_SERVER['SERVER_PROTOCOL'], 5),
			'authLevel' => $this->request['authLevel'],
			'priority' => $this->request['priority'],
			'method' => $_SERVER['REQUEST_METHOD'],
			'path' => $_SERVER['PATH_INFO'],
			'requestHeaders' => $log_in_headers,
			'requestData' => $logRequestData,
			'usedTime' => intval(($now_time - $this->serveStartTime) * 1000000000) / 1000000,
			'fullUsedTime' => intval(($now_time - $_SERVER['REQUEST_TIME']) * 1000000000) / 1000000,
			'responseCode' => http_response_code(),
			'responseHeaders' => $log_out_headers,
			'responseDataLength' => $responseDataLength,
			'responseData' => $logResponseData,
		]);
	}

	function fixSensitive($data, $level = 0)
	{
		if ($level > 10) return $data;
		if (!is_array($data)) return $data;
		if (isset($data[0])) {
			$data = [$this->fixSensitive($data[0]), $level + 1];
		} else {
			foreach ($data as $k => $v) {
				if (is_array($v)) {
					$data[$k] = $this->fixSensitive($v, $level + 1);
				} else {
					if (in_array(strtoupper($k), $this->config['LOG_SENSITIVE'])) $data[$k] = $this->getSensitiveStr($v);
				}
			}
		}
		return $data;
	}

	function getSensitiveStr($str)
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

	function info($msg, $extra = null)
	{
		$this->log([
			'logType' => 'info',
			'info' => $msg,
		], $extra);
	}

	function error($msg, $extra = null)
	{
		$this->log([
			'logType' => 'error',
			'error' => $msg,
			'callStacks' => $this->getCallStacks(),
		], $extra);
	}

	function warning($msg, $extra = null)
	{
		$this->log([
			'logType' => 'warning',
			'warning' => $msg,
			'callStacks' => $this->getCallStacks(),
		], $extra);
	}

	function debug($msg, $extra = null)
	{
		$this->log([
			'logType' => 'debug',
			'debug' => $msg,
			'callStacks' => $this->getCallStacks(),
		], $extra);
	}

	protected function getCallStacks()
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


	function errorHandler($errno, $errstr, $errfile, $errline, $errcontext)
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
			$this->error($errstr, $info);
		} else if ($errno == E_WARNING || $errno == E_USER_WARNING) {
			$this->warning($errstr, $info);
		}
		return true;
	}

	function shutdownHandler()
	{
		if ($error = error_get_last()) {
			$errno = $error['type'];
//            if ($errno == E_ERROR || $errno == E_WARNING || $errno == E_USER_ERROR || $errno == E_USER_WARNING) {
			if ($errno == E_ERROR || $errno == E_USER_ERROR) {
				$this->error('500 Internal Server Error', $error);
				http_response_code(500);
				$result = [];
				$this->logRequest($result, 2);
				echo '{}';
			}
		}
	}

	function defaultAuthChecker($authLevel, $apiName, $requestData)
	{
		$settedAuthLevel = $this->config['SERVICE_ACCESSTOKENS'][$_SERVER['HTTP_ACCESS_TOKEN']];
		return $settedAuthLevel && $settedAuthLevel >= $authLevel;
	}

	function ok($data, $code = 1, $message = '')
	{
		return [
			'code' => $code,
			'message' => $message,
			'data' => $data
		];
	}

	function failed($code = -1, $message = '', $data = null)
	{
		return [
			'code' => $code,
			'message' => $message,
			'data' => $data
		];
	}

	function getDB($name = '')
	{
		if ($this->pdos[$name . '_']) return $this->pdos[$name . '_'];
		$prefix = 'DB_';
		if ($name !== '') $prefix = 'DB_' . strtoupper($name) . '_';
		if (!$this->config[$prefix . 'OPTIONS']) $this->config[$prefix . 'OPTIONS'] = [
			PDO::ATTR_TIMEOUT => 3,
			PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES 'UTF8'",
			PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
			PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
			PDO::ATTR_EMULATE_PREPARES => false,
			PDO::ATTR_STRINGIFY_FETCHES => false,
			PDO::ATTR_PERSISTENT => false,
		];
		$pdo = new PDO($this->config[$prefix . 'DSN'], $this->config[$prefix . 'USER'], $this->decryptPassword($this->config[$prefix . 'PASSWORD']), $this->config[$prefix . 'OPTIONS']);
		$this->pdos[$name . '_'] = $pdo;
		return $pdo;
	}

	function getRedis($name = '')
	{
		if ($this->redises[$name . '_']) return $this->redises[$name . '_'];
		$prefix = 'REDIS_';
		if ($name !== '') $prefix = 'REDIS_' . strtoupper($name) . '_';
		list($host, $port, $n) = explode(':', $this->config[$prefix . 'HOST']);
		if (!$host) $host = '127.0.0.1';
		if (!$port) $port = 6379;
		if (!$n || $n < 0 || $n > 15) $n = 0;
		$redis = new Redis();
		$redis->connect($host, $port);
		if ($this->config[$prefix . 'PASSWORD']) {
			$redis->auth($this->decryptPassword($this->config[$prefix . 'PASSWORD']));
		}
		if ($n) {
			$redis->select($n);
		}
		return $redis;
	}

	function decryptPassword($str)
	{
		$decrypted = @mcrypt_decrypt(MCRYPT_RIJNDAEL_128, substr($this->encrypt, 0, 32), base64_decode($str), MCRYPT_MODE_CBC, substr($this->encrypt, 32));
		$pwd = substr($decrypted, 0, -ord($decrypted[strlen($decrypted) - 1]));
		if (!$pwd) $pwd = $str;
		return $pwd;
	}
}
