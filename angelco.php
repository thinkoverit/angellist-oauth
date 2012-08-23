<?php
/**
 * CodeIgniter Angel.co API Library (http://thinkoverit.com)
 * 
 * Author: Pandurang Zambare, pandu@thinkoverit.com
 *
 * This is Librarry Class for Codeigniter Framework.
 * ========================================================
 * REQUIRES: php5, curl, json_decode
 * ========================================================
 * 
 * VERSION: 1.0 (Dec 2011)
 * LICENSE: GNU GENERAL PUBLIC LICENSE - Version 2, June 1991
 * 
 **/
class Angelco {
	
	private $_oauth = NULL;
	
	function __construct()
	{
		$this->_oauth = new angelcoOauth();
	}
	
	function __call($method, $args)
	{
		if ( method_exists($this, $method) )
		{
			return call_user_func_array(array($this, $method), $args);
		}
		
		return call_user_func_array(array($this->_oauth, $method), $args);
	}
	
	function logged_in()
	{
		return $this->_oauth->loggedIn();
	}
	
	function set_callback($url)
	{
		$this->_oauth->setCallback($url);
	}
	
	function login()
	{
		return $this->_oauth->login();
	}
	
	function logout()
	{
		return $this->_oauth->logout();
	}
	
	function get_tokens()
	{
		$tokens =$this->_oauth->getAccessSecret();
					
		return $tokens;
	}
	
	function set_tokens($tokens)
	{
		return $this->_oauth->setAccessTokens($tokens);
	}
}

class angelcoException extends Exception {
	
	function __construct($string)
	{
		parent::__construct($string);
	}
	
	public function __toString() {
		return "exception '".__CLASS__ ."' with message '".$this->getMessage()."' in ".$this->getFile().":".$this->getLine()."\nStack trace:\n".$this->getTraceAsString();
	}
}

class angelcoConnection {
	
	
	private $_mch = NULL;
	private $_properties = array();
	
	function __construct()
	{
		$this->_mch = curl_multi_init();
		
		$this->_properties = array(
			'code' 		=> CURLINFO_HTTP_CODE,
			'time' 		=> CURLINFO_TOTAL_TIME,
			'length'	=> CURLINFO_CONTENT_LENGTH_DOWNLOAD,
			'type' 		=> CURLINFO_CONTENT_TYPE
		);
	}
	
	private function _initConnection($url)
	{
		$this->_ch = curl_init($url);
		curl_setopt($this->_ch, CURLOPT_RETURNTRANSFER, TRUE);
	}
	
	public function get($url, $params)
	{
		if ( count($params) > 0 )
		{
			$url .= '?';
		
			foreach( $params as $k => $v )
			{
				$url .= "{$k}={$v}&";
			}
			
			$url = substr($url, 0, -1);
		}
		
		$this->_initConnection($url);
		$response = $this->_addCurl($url, $params);

		return $response;
	}
	
	public function post($url, $params)
	{
		$post = '';
		
		foreach ( $params as $k => $v )
		{
			$post .= "{$k}={$v}&";
		}
		
		$post = substr($post, 0, -1);
		
		$this->_initConnection($url, $params);
		curl_setopt($this->_ch, CURLOPT_POST, 1);
		curl_setopt($this->_ch, CURLOPT_POSTFIELDS, $post);
		
		$response = $this->_addCurl($url, $params);

		return $response;
	}
	
	private function _addOauthHeaders(&$ch, $url, $oauthHeaders)
	{
		$_h = array('Expect:');
		$urlParts = parse_url($url);
		$oauth = 'Authorization: OAuth realm="' . $urlParts['path'] . '",';
		
		foreach ( $oauthHeaders as $name => $value )
		{
			$oauth .= "{$name}=\"{$value}\",";
		}
		
		$_h[] = substr($oauth, 0, -1);
		
		curl_setopt($ch, CURLOPT_HTTPHEADER, $_h);
	}
	
	private function _addCurl($url, $params = array())
	{

		$ch = $this->_ch;
		
		$key = (string) $ch;
		$this->_requests[$key] = $ch;
		
		$response = curl_multi_add_handle($this->_mch, $ch);

		if ( $response === CURLM_OK || $response === CURLM_CALL_MULTI_PERFORM )
		{
			do {
				$mch = curl_multi_exec($this->_mch, $active);
			} while ( $mch === CURLM_CALL_MULTI_PERFORM );
			
			return $this->_getResponse($key);
		}
		else
		{
			return $response;
		}
	}
	
	private function _getResponse($key = NULL)
	{
		if ( $key == NULL ) return FALSE;
		
		if ( isset($this->_responses[$key]) )
		{
			return $this->_responses[$key];
		}
		
		$running = NULL;
		
		do
		{
			$response = curl_multi_exec($this->_mch, $running_curl);
			
			if ( $running !== NULL && $running_curl != $running )
			{
				$this->_setResponse($key);
				
				if ( isset($this->_responses[$key]) )
				{
					$response = new angelcoResponseOauth( (object) $this->_responses[$key] );
				
					if ( $response->__resp->code !== 200 )
					{
						throw new angelcoException($response->__resp->code.' | Request Failed: ');
					}
					
					return $response;
				}
			}
			
			$running = $running_curl;
			
		} while ( $running_curl > 0);
		
	}
	
	private function _setResponse($key)
	{
		while( $done = curl_multi_info_read($this->_mch) )
		{
			$key = (string) $done['handle'];
			$this->_responses[$key]['data'] = curl_multi_getcontent($done['handle']);
			
			foreach ( $this->_properties as $curl_key => $value )
			{
				$this->_responses[$key][$curl_key] = curl_getinfo($done['handle'], $value);
				
				curl_multi_remove_handle($this->_mch, $done['handle']);
			}
	  }
	}
}

class angelcoResponseOauth {
	
	private $__construct;

	public function __construct($resp)
	{
		$this->__resp = $resp;

		if ( strpos($this->__resp->type, 'json') !== FALSE )
		{
			$this->__resp->data = json_decode($this->__resp->data);
		}
	}

	public function __get($name)
	{
		if ($this->__resp->code < 200 || $this->__resp->code > 299) return FALSE;
		
		if ( is_string($this->__resp->data ) )
		{
			$result = json_decode($this->__resp->data);
//				parse_str($this->__resp->data, $result);
		}
		else
		{
			$result = $this->__resp->data;
		}
		
		foreach($result as $k => $v)
		{
			$this->$k = $v;
		}
		
		if ( $name === '_result')
		{
			return $result;
		}

		return $result[$name];
	}
}

class angelcoOauth extends angelcoConnection {
	
	private $_obj;
	private $_tokens = array();
	private $_authorizationUrl 	= 'https://angel.co/api/oauth/authorize';
	private $_accessTokenUrl 	= 'https://angel.co/api/oauth/token';
	private $_signatureMethod 	= 'HMAC-SHA1';
	private $_version 			= '1.0';
	private $_apiUrl 			= 'https://api.angel.co/1';
	private $_callback = NULL;
	private $_errors = array();
	private $_enable_debug = FALSE;
	private $clientID;
	private $clientSecret;
	
	function __construct()
	{
		parent::__construct();
		
		$this->_obj =& get_instance();
		$this->_obj->load->config('angellist_config');
		$this->_obj->load->library('session');
		$this->_obj->load->helper('url');
		
		$this->_tokens =$this->_getAccessSecret();
		$this->clientID = $this->_obj->config->item('ANGELLIST_CONSUMERKEY');
		$this->clientSecret = $this->_obj->config->item('ANGELLIST_CONSUMERSECRET');

		$this->_checkLogin();
	}
	
	function __destruct()
	{
		if ( !$this->_enable_debug ) return;
		
		if ( !empty($this->_errors) )
		{
			foreach ( $this->_errors as $key => $e )
			{
				echo '<pre>'.$e.'</pre>';
			}
		}
	}
	
	public function enable_debug($debug)
	{
		$debug = (bool) $debug;
		$this->_enable_debug = $debug;
	}
	
	public function call($method, $path, $args = NULL)
	{
		$user = $this->_apiUrl.'/'.$path.'?access_token='.$this->_getAccessSecret();
		$response = $this->_httpRequest(strtoupper($method), $user , $args);
		
		// var_dump($response);
		 //die();
		
		return ( $response === NULL ) ? FALSE : $response->_result;
	}
	
	public function search($args = NULL)
	{
		$response = $this->_httpRequest('GET', $this->_searchUrl.'search.json', $args);
		
		return ( $response === NULL ) ? FALSE : $response->_result;
	}
	
	public function loggedIn()
	{

		$loggedIn = FALSE;
		
		if ($this->_getAccessSecret() !== NULL )
		{
			$loggedIn = TRUE;
		}
		
		$this->_obj->unit->run($loggedIn, TRUE, 'Logged In');
		return $loggedIn;
	}

	
	public function login()
	{
		if ($this->_getAccessSecret() === NULL)
		{
			header('Location: '.$this->_getAuthorizationUrl());
			return;
		}
		
		return $this->_checkLogin();
	}
	
	private function _checkLogin()
	{
		if ( isset($_GET['code']) )
		{
			$token = $this->_getAccessToken();
			$token = $token->_result;
			
			
			if ( !empty($token) && isset($token->access_token))
			{
				$this->setAccessTokens($token->access_token);
			}

			
			return true;
		}
		return false;
	}
	
	public function logout()
	{
		$this->_obj->session->unset_userdata('angelco_oauth_tokens');
	}
	
	public function getTokens()
	{
		return $this->_tokens;
	}
	
	private function _getConsumerKey()
	{
		return $this->_tokens['consumer_key'];
	}
	
	private function _getConsumerSecret()
	{
		return $this->_tokens['consumer_secret'];
	}

	public function getAccessSecret(){ return $this->_getAccessSecret(); }
	
	private function _getAccessSecret()
	{
		$token = $this->_obj->session->userdata('angelco_oauth_tokens');
		return (empty($token)) ? NULL : $token;
	}


	
	public function setAccessTokens($tokens)
	{
		$this->_obj->session->set_userdata('angelco_oauth_tokens', $tokens);
	}
	
	private function _getAuthorizationUrl()
	{
		return $this->_authorizationUrl.'?response_type=code&client_id=' . $this->clientID;
	}

	
	private function _getAccessToken()
	{
		$params['client_id'] = $this->clientID;
		$params['client_secret'] = $this->clientSecret;
		$params['code'] = $_GET['code'];
		$params['grant_type'] = "authorization_code";

		return $this->_httpRequest('POST', $this->_accessTokenUrl, $params);
	}
	
	protected function _httpRequest($method = null, $url = null, $params = null)
	{
		if( empty($method) || empty($url) ) return FALSE;
//if ( empty($params['oauth_signature']) ) $params = $this->_prepareParameters($method, $url, $params);
		
		$this->_connection = new angelcoConnection();
		
		try {
			switch ( $method )
			{
				case 'GET':
					return $this->_connection->get($url, $params);
				break;

				case 'POST':
					return $this->_connection->post($url, $params);
				break;

			}
		} catch (angelcoException $e) {
			$this->_errors[] = $e;
		}
	}
	
	private function _getCallback()
	{
		return $this->_callback;
	}
	
	public function setCallback($url)
	{
		$this->_callback = $url;
	}
	
	private function _prepareParameters($method = NULL, $url = NULL, $params = NULL)
	{
		if ( empty($method) || empty($url) ) return FALSE;
		
		$callback = $this->_getCallback();
		
		if ( !empty($callback) )
		{
			$oauth['oauth_callback'] = $callback;
		}
		
		$this->setCallback(NULL);
		
		$oauth['oauth_consumer_key'] 		= $this->_getConsumerKey();
		$oauth['oauth_nonce'] 				= $this->_generateNonce();
		$oauth['oauth_timestamp'] 			= time();
		$oauth['oauth_signature_method'] 	= $this->_signatureMethod;
		$oauth['oauth_version'] 			= $this->_version;
		
		array_walk($oauth, array($this, '_encode_rfc3986'));
		
		if ( is_array($params) )
		{
			array_walk($params, array($this, '_encode_rfc3986'));
		}
		
		$encodedParams = array_merge($oauth, (array)$params);
		
		ksort($encodedParams);
		
		$oauth['oauth_signature'] = $this->_encode_rfc3986($this->_generateSignature($method, $url, $encodedParams));
		return array('request' => $params, 'oauth' => $oauth);
	}

	private function _generateNonce()
	{
		return md5(uniqid(rand(), TRUE));
	}
	
	private function _encode_rfc3986($string)
	{
		return str_replace('+', ' ', str_replace('%7E', '~', rawurlencode(($string))));
	}
	
	private function _generateSignature($method = null, $url = null, $params = null)
	{
		if( empty($method) || empty($url) ) return FALSE;
		
		// concatenating
		$concatenatedParams = '';
		
		foreach ($params as $k => $v)
		{
			$v = $this->_encode_rfc3986($v);
			$concatenatedParams .= "{$k}={$v}&";
		}
		
		$concatenatedParams = $this->_encode_rfc3986(substr($concatenatedParams, 0, -1));

		// normalize url
		$normalizedUrl = $this->_encode_rfc3986($this->_normalizeUrl($url));
		$method = $this->_encode_rfc3986($method); // don't need this but why not?

		$signatureBaseString = "{$method}&{$normalizedUrl}&{$concatenatedParams}";
		return $this->_signString($signatureBaseString);
	}
	
	private function _normalizeUrl($url = NULL)
	{
		$urlParts = parse_url($url);

		if ( !isset($urlParts['port']) ) $urlParts['port'] = 80;

		$scheme = strtolower($urlParts['scheme']);
		$host = strtolower($urlParts['host']);
		$port = intval($urlParts['port']);

		$retval = "{$scheme}://{$host}";
		
		if ( $port > 0 && ( $scheme === 'http' && $port !== 80 ) || ( $scheme === 'https' && $port !== 443 ) )
		{
			$retval .= ":{$port}";
		}
		
		$retval .= $urlParts['path'];
		
		if ( !empty($urlParts['query']) )
		{
			$retval .= "?{$urlParts['query']}";
		}
		
		return $retval;
	}
	
	private function _signString($string)
	{
		$retval = FALSE;
		switch ( $this->_signatureMethod )
		{
			case 'HMAC-SHA1':
				$key = $this->_encode_rfc3986($this->_getConsumerSecret()) . '&' . $this->_encode_rfc3986($this->_getAccessSecret());
				$retval = base64_encode(hash_hmac('sha1', $string, $key, true));
			break;
		}

		return $retval;
	}

}