<?php

/**
 * This file is part of yubico-php-client
 *
 * @copyright Yubico 2014
 *
 * This source file is subject to the license that is bundled
 * with this source code in the file LICENSE
 */

namespace Yubico;

/**
 * @author Simon Josefsson <simon@yubico.com>
 * @author Olov Danielson <olov@yubico.com>
 * @author Aaron Scherer <aequasi@gmail.com>
 */
class YubiCloud
{
    /**
     * Yubico client ID
     *
     * @type string
     */
    protected $id;

    /**
     * Yubico client key
     *
     * @type string
     */
    protected $key;

    /**
     * Flag whether to use https or not.
     *
     * @type bool
     */
    protected $https;

    /**
     * Flag whether to verify HTTPS server certificates or not.
     *
     * @type bool
     */
    protected $httpsVerify;

    /**
     * urls
     *
     * @internal
     */
    protected $urls = [
        'api.yubico.com/wsapi/2.0/verify',
        'api2.yubico.com/wsapi/2.0/verify',
        'api3.yubico.com/wsapi/2.0/verify',
        'api4.yubico.com/wsapi/2.0/verify',
        'api5.yubico.com/wsapi/2.0/verify'
    ];

    /**
     * Last query to server
     *
     * @type string
     */
    protected $lastQuery;

    /**
     * Response from server
     *
     * @type string
     */
    protected $response;

    /**
     * Constructor
     *
     * Sets up the object
     *
     * @param string $id               The client identity
     * @param string $key              The client MAC key (optional)
     * @param bool   $https            Flag whether to use https (optional)
     * @param bool   $httpsVerify      Flag whether to use verify HTTPS
     *                                 server certificates (optional,
     *                                 default true)
     *
     * @access public
     */
    public function __construct($id, $key = '', $https = false, $httpsVerify = true)
    {
        $this->id          = $id;
        $this->key         = base64_decode($key);
        $this->https       = $https;
        $this->httpsVerify = $httpsVerify;
    }

    /**
     * Specify to use a different URL part for verification.
     *
     * Pass in an array of strings indicating the hostname and path part
     * of the URL, as http or https as prepended by the library.  For
     * example, array("api.example.com/wsapi/2.0/verify",
     * "api2.example.com/wsapi/2.0/verify").
     *
     * @param array $urls Array with server URL parts to use
     */
    public function setURLparts($urls)
    {
        $this->urls = $urls;
    }

    /**
     * Get array of URL parts to use for validation.
     *
     * @return array
     */
    public function getURLparts()
    {
        return $this->urls;
    }

    /**
     * Return the last query sent to the server, if any.
     *
     * @return string  Request to server
     */
    public function getLastQuery()
    {
        return $this->lastQuery;
    }

    /**
     * Return the last data received from the server, if any.
     *
     * @return string  Output from server
     */
    public function getLastResponse()
    {
        return $this->response;
    }

    /**
     * Parse input string into password, yubikey prefix,
     * ciphertext, and OTP.
     *
     * @param string $str   Input string to parse
     * @param string $delim Optional delimiter re-class, default is '[:]'
     *
     * @return array     Keyed array with fields
     */
    public function parsePasswordOTP($str, $delim = '[:]')
    {
        if (!preg_match("/^((.*)".$delim.")?".
            "(([cbdefghijklnrtuv]{0,16})".
            "([cbdefghijklnrtuv]{32}))$/i",
            $str, $matches)
        ) {
            /* Dvorak? */
            if (!preg_match("/^((.*)".$delim.")?".
                "(([jxe\.uidchtnbpygk]{0,16})".
                "([jxe\.uidchtnbpygk]{32}))$/i",
                $str, $matches)
            ) {
                return false;
            } else {
                $ret['otp'] = strtr($matches[3], "jxe.uidchtnbpygk", "cbdefghijklnrtuv");
            }
        } else {
            $ret['otp'] = $matches[3];
        }
        $ret['password']   = $matches[2];
        $ret['prefix']     = $matches[4];
        $ret['ciphertext'] = $matches[5];

        return $ret;
    }

    /* TODO? Add functions to get parsed parts of server response? */

    /**
     * Parse parameters from last response
     *
     * example: getParameters("timestamp", "sessioncounter", "sessionuse");
     *
     * @param array $parameters Array with strings representing parameters to parse
     *
     * @throws \Exception
     * @return array  parameter array from last response
     */
    public function getParameters($parameters)
    {
        if ($parameters == null) {
            $parameters = ['timestamp', 'sessioncounter', 'sessionuse'];
        }
        $param_array = [];
        foreach ($parameters as $param) {
            if (!preg_match("/".$param."=([0-9]+)/", $this->response, $out)) {
                throw new \Exception("Could not parse parameter \"{$param}\" from response.");
            }
            $param_array[$param] = $out[1];
        }

        return $param_array;
    }

    /**
     * Verify Yubico OTP against multiple URLs
     * Protocol specification 2.0 is used to construct validation requests
     *
     * @param string $token        Yubico OTP
     * @param int    $useTimestamp 1=>send request with &timestamp=1 to get timestamp and session information
     * @param bool   $waitForAll   If true, wait until all servers responds (for debugging)
     * @param string $sl           Sync level in percentage between 0 and 100 or "fast" or "secure".
     * @param int    $timeout      Max number of seconds to wait for responses
     *
     * @throws \Exception
     * @return bool
     */
    public function verify($token, $useTimestamp = null, $waitForAll = false, $sl = null, $timeout = null)
    {
        /* Construct parameters string */
        $ret = $this->parsePasswordOTP($token);
        if (!$ret) {
            throw new \Exception("Could not parse Yubikey OTP");
        }
        $params = [
            'id'    => $this->id,
            'otp'   => $ret['otp'],
            'nonce' => md5(uniqid(rand()))
        ];
        /* Take care of protocol version 2 parameters */
        if ($useTimestamp) {
            $params['timestamp'] = 1;
        }
        if ($sl) {
            $params['sl'] = $sl;
        }
        if ($timeout) {
            $params['timeout'] = $timeout;
        }
        ksort($params);
        $parameters = '';
        foreach ($params as $p => $v) {
            $parameters .= "&".$p."=".$v;
        }
        $parameters = ltrim($parameters, "&");

        /* Generate signature. */
        if ($this->key <> "") {
            $signature = base64_encode(hash_hmac('sha1', $parameters,
                $this->key, true));
            $signature = preg_replace('/\+/', '%2B', $signature);
            $parameters .= '&h='.$signature;
        }

        /* Generate and prepare request. */
        $this->lastQuery = null;
        $this->URLreset();
        $mh = curl_multi_init();
        $ch = [];
        while ($URLpart = $this->getNextURLpart()) {
            /* Support https. */
            if ($this->https) {
                $query = "https://";
            } else {
                $query = "http://";
            }
            $query .= $URLpart."?".$parameters;

            if ($this->lastQuery) {
                $this->lastQuery .= " ";
            }
            $this->lastQuery .= $query;

            $handle = curl_init($query);
            curl_setopt($handle, CURLOPT_USERAGENT, "PEAR Auth_Yubico");
            curl_setopt($handle, CURLOPT_RETURNTRANSFER, 1);
            if (!$this->httpsVerify) {
                curl_setopt($handle, CURLOPT_SSL_VERIFYPEER, 0);
                curl_setopt($handle, CURLOPT_SSL_VERIFYHOST, 0);
            }
            curl_setopt($handle, CURLOPT_FAILONERROR, true);
            /* If timeout is set, we better apply it here as well
               in case the validation server fails to follow it. 
            */
            if ($timeout) {
                curl_setopt($handle, CURLOPT_TIMEOUT, $timeout);
            }
            curl_multi_add_handle($mh, $handle);

            $ch[(int)$handle] = $handle;
        }

        /* Execute and read request. */
        $this->response = null;
        $replay         = false;
        $valid          = false;
        do {
            /* Let curl do its work. */
            while (($mrc = curl_multi_exec($mh, $active))
                == CURLM_CALL_MULTI_PERFORM) {
                ;
            }

            while ($info = curl_multi_info_read($mh)) {
                if ($info['result'] == CURLE_OK) {

                    /* We have a complete response from one server. */

                    $str   = curl_multi_getcontent($info['handle']);
                    $cinfo = curl_getinfo($info['handle']);

                    if ($waitForAll) { # Better debug info
                        $this->response .= 'URL='.$cinfo['url']."\n"
                            .$str."\n";
                    }

                    if (preg_match("/status=([a-zA-Z0-9_]+)/", $str, $out)) {
                        $status = $out[1];

                        /* 
                         * There are 3 cases.
                         *
                         * 1. OTP or Nonce values doesn't match - ignore
                         * response.
                         *
                         * 2. We have a HMAC key.  If signature is invalid -
                         * ignore response.  Return if status=OK or
                         * status=REPLAYED_OTP.
                         *
                         * 3. Return if status=OK or status=REPLAYED_OTP.
                         */
                        if (!preg_match("/otp=".$params['otp']."/", $str) ||
                            !preg_match("/nonce=".$params['nonce']."/", $str)
                        ) {
                            /* Case 1. Ignore response. */
                        } elseif ($this->key <> "") {
                            /* Case 2. Verify signature first */
                            $rows     = explode("\r\n", trim($str));
                            $response = [];
                            while (list($key, $val) = each($rows)) {
                                /* = is also used in BASE64 encoding so we only replace the first = by # which is not used in BASE64 */
                                $val               = preg_replace('/=/', '#', $val, 1);
                                $row               = explode("#", $val);
                                $response[$row[0]] = $row[1];
                            }

                            $parameters = [
                                'nonce',
                                'otp',
                                'sessioncounter',
                                'sessionuse',
                                'sl',
                                'status',
                                't',
                                'timeout',
                                'timestamp'
                            ];
                            sort($parameters);
                            $check = null;
                            foreach ($parameters as $param) {
                                if (array_key_exists($param, $response)) {
                                    if ($check) {
                                        $check = $check.'&';
                                    }
                                    $check = $check.$param.'='.$response[$param];
                                }
                            }

                            $checksignature =
                                base64_encode(hash_hmac('sha1', utf8_encode($check),
                                    $this->key, true));

                            if ($response['h'] == $checksignature) {
                                if ($status == 'REPLAYED_OTP') {
                                    if (!$waitForAll) {
                                        $this->response = $str;
                                    }
                                    $replay = true;
                                }
                                if ($status == 'OK') {
                                    if (!$waitForAll) {
                                        $this->response = $str;
                                    }
                                    $valid = true;
                                }
                            }
                        } else {
                            /* Case 3. We check the status directly */
                            if ($status == 'REPLAYED_OTP') {
                                if (!$waitForAll) {
                                    $this->response = $str;
                                }
                                $replay = true;
                            }
                            if ($status == 'OK') {
                                if (!$waitForAll) {
                                    $this->response = $str;
                                }
                                $valid = true;
                            }
                        }
                    }
                    if (!$waitForAll && ($valid || $replay)) {
                        /* We have status=OK or status=REPLAYED_OTP, return. */
                        foreach ($ch as $h) {
                            curl_multi_remove_handle($mh, $h);
                            curl_close($h);
                        }
                        curl_multi_close($mh);
                        if ($replay) {
                            throw new \Exception("REPLAYED_OTP");
                        }
                        if ($valid) {
                            return true;
                        }

                        throw new \Exception($status);
                    }

                    curl_multi_remove_handle($mh, $info['handle']);
                    curl_close($info['handle']);
                    unset ($ch[(int)$info['handle']]);
                }
                curl_multi_select($mh);
            }
        } while ($active);

        /* Typically this is only reached for wait_for_all=true or
         * when the timeout is reached and there is no
         * OK/REPLAYED_REQUEST answer (think firewall).
         */

        foreach ($ch as $h) {
            curl_multi_remove_handle($mh, $h);
            curl_close($h);
        }
        curl_multi_close($mh);

        if ($replay) {
            throw new \Exception("REPLAYED_OTP");
        }
        if ($valid) {
            return true;
        }

        throw new \Exception("NO_VALID_ANSWER");
    }
}
