<?php
/**
 * Botbouncer class
 *
 * The purpose of this class is to have a single interface to multiple anti-comment-spam services on the internet.
 * That way, you can write your application code to check for spam and decide which of the services to use
 * to actually identify the spam.
 *
 *
 * Currently supported:
 *
 * StopForumSpam: http://www.stopforumspam.com
 *
 * Project Honeypot: http://www.projecthoneypot.org
 *
 * Akismet: http://www.akismet.com
 *
 * Mollom: http://www.mollom.com
 *
 * @author Michiel Dethmers, phpList Ltd, http://www.phplist.com
 * @version 0.3 - Apr 23, 2013 - renamed Botbouncer (from FormspamCheck.class)
 * @version 0.2 - Sept 8th 2011 - added Mollom support
 *
 * version 0.1 - 24 August 2011
 * @license LGPL (Lesser Gnu Public License) http://www.gnu.org/licenses/lgpl-3.0.html
 * @package Botbouncer
 * Free to use, distribute and modify in Open as well as Closed Source software
 * NO WARRANTY WHATSOEVER!
 * ---------------
 *
 * For more information and how to set up and configure, http://www.botbouncer.org/
 *
 * It currently uses three services, stopforumspam.com, project honeypot and akismet
 * If you know of any other services that can be integrated, let me know.
 *
 * Credits: Very loosely based on the original phpBB mod from "microUgly"
 * http://www.phpbb.com/community/viewtopic.php?f=70&t=1349145
 *
 *
 */


/**
 * Botbouncer class, centralised spam protection
 *
 * Check form submission against multipe spam protection sources
 *
 * @example example.php
 *
 * @package Botbouncer
 * @subpackage classes
 *
 */
class Botbouncer {

  /** var LE - line ending */
  private $LE = "\n";
  private $sfsEnabled = true;
  private $honeyPotApiKey = '';
  private $akismetApiKey = '';
  private $akismetBlogURL = 'http://www.yoursite.com';
  private $memCached = false;
  private $doHpCheck = false;
  private $akismetEnabled = false;
  private $logRoot = '/var/log/botbouncer';
  private $logActivity = true;
  private $debug = false;
  private $debugToLog = true;
  private $UA = 'Botbouncer (v.0.3)';
  // The StopFormSpam API URL
  private $stopSpamAPIUrl = 'https://api.stopforumspam.org/api';
  private $startTime = 0;
  private $mollomCheck = '';
  private $mollomEnabled = false;
  private $ipIntelEnabled = false;
  private $ipIntelAPIUrl = 'http://check.getipintel.net/check.php';
  private $ipIntelContact = ''; // IP Intel requires a contact e-mail address
  private $ipIntelSpamThreshold = 0.99; // Per API's recommendation for automated systems

  /**
   * (array) matchDetails - further details on a match provided by SFS
   */

  public $matchDetails = '';

  /**
   * (string) matchedBy - which service returned the match when isSpam returns true
   */

  public $matchedBy = '';

  /**
   * (string) matchedOn - what field was matched when isSpam returns true
   */

  public $matchedOn = '';

  /**
   * (bool) isSpam - flag indicating spam (true) or ham (false) after running any spamcheck
   */
  public $isSpam = false;

  private $services = array(
    'SFS' => 'Stop Forum Spam',
    'HP' => 'Honeypot Project',
    'AKI' => 'Akismet',
    'MOL' => 'Mollom',
    'IPI' => 'IP Intel'
  );

  private $sfsSpamTriggers = array ( ## set a default, in case it's not in config
    'username' => array (
      'ban_end' => FALSE,
      'freq_tolerance' => 2,
      'ban_reason' => 'You have been identified as a spammer.',
    ),
    'email' => array (
      'ban_end' => FALSE,
      'freq_tolerance' => 0,
      'ban_reason' => 'You have been identified as a spammer.',
    ),
    'ip' => array (
      'ban_end' => 604800,// 7 days
      'freq_tolerance' => 1,
      'ban_reason' => 'You have been identified as a spammer.',
    )
  );

  private $akismetFields = array(
      'blog',
      'user_ip',
      'user_agent',
      'referrer',
      'permalink',
      'comment_type',
      'comment_author',
      'comment_author_email',
      'comment_author_url',
      'comment_content'
  );

  public function setDebug($setting) {
    $this->debug = (bool)$setting;
    $this->debugToLog = (bool) $setting;
  }

  /**
   * constructor
   *
   * initialise class with services available. There's no need to use all, if any service is not
   * configured, the check for it will be disabled automatically
   *
   * @param string $hpKey - API key for Honeypot Project
   * @param string $akismetKey - API key for Akismet service
   * @param string $akismetUrl - BlogURL for Akismet service
   * @param string $ipIntelContact - Contact email for IP Intel
   *
   */

  public function __construct($hpKey = '',$akismetKey = '',$akismetUrl = '', $mollomPrivateKey = '',$mollomPublicKey = '', $ipIntelContact = '') {
    if (!function_exists('curl_init')) {
      print 'curl dependency error';
      return;
    }
    $this->dbg('FSC Init');
    if (!empty($hpKey)) {
      $this->honeyPotApiKey = $hpKey;
      $this->doHpCheck = true;
    } elseif (!empty($GLOBALS['honeyPotApiKey'])) {
      $this->honeyPotApiKey = $GLOBALS['honeyPotApiKey'];
      $this->doHpCheck = true;
    }
    if (!empty($akismetKey)) {
      $this->akismetApiKey = $akismetKey;
      $this->akismetEnabled = true;
    } elseif (!empty($GLOBALS['akismetApiKey'])) {
      $this->akismetApiKey = $GLOBALS['akismetApiKey'];
      $this->akismetEnabled = true;
    }
    if (!empty($akismetUrl)) {
      $this->akismetBlogURL = $akismetUrl;
    } elseif (!empty($GLOBALS['akismetBlogURL'])) {
      $this->akismetBlogURL = $GLOBALS['akismetBlogURL'];
      ## @todo verify validity
    } elseif (!empty($_SERVER['HTTP_HOST'])) {
      $this->akismetBlogURL = $_SERVER['HTTP_HOST'];
    }

    if (!empty($ipIntelContact)) {
        $this->ipIntelContact = $ipIntelContact;
        $this->ipIntelEnabled = true;
    } elseif (!empty($GLOBALS['ipIntelContact'])) {
        $this->ipIntelContact = $GLOBALS['ipIntelContact'];
        $this->ipIntelEnabled = true;
    }

    if (!empty($GLOBALS['logRoot']) && is_writable($GLOBALS['logRoot'])) {
      $this->logRoot = $GLOBALS['logRoot'];
    }
    if (isset($GLOBALS['ForumSpamBanTriggers'])) {
      $this->spamTriggers = $GLOBALS['ForumSpamBanTriggers'];
    }
    if (isset($GLOBALS['sfsEnabled'])) {
      $this->sfsEnabled = (bool) $GLOBALS['sfsEnabled'];
    }

    if (isset($GLOBALS['memCachedServer']) && class_exists('Memcached', false)) {
      $this->setMemcached($GLOBALS['memCachedServer']);
    } else {
      if (!class_exists('Memcached',false)) {
        $this->dbg('memcache not available, class "Memcached" not found');
      } else {
        $this->dbg('memcache not available, config "memCachedServer" not set');
      }
    }

    if (is_file(dirname(__FILE__).'/mollom.php') && !empty($mollomPrivateKey) && !empty($mollomPublicKey)) {
      $this->dbg('loading mollom');
      @include dirname(__FILE__).'/mollom.php';
      if (class_exists('Mollom',false)) {
        $this->mollomCheck = new Mollom();
        $this->dbg('mollom instantiated');
        try {
          $this->mollomCheck->setPrivateKey($mollomPrivateKey);
          $this->mollomCheck->setPublicKey($mollomPublicKey);
          $serverList = $this->getCache('mollomServerList');
          if (empty($serverList)) {
            $serverList = $this->mollomCheck->getServerList();
            $this->setCache('mollomServerList',$serverList);
          } else {
            $this->mollomCheck->setServerList($serverList);
          }
          $validKey = $this->getCache('mollomKeyValid');
          if ($validKey == 'YES') {
            $this->mollomEnabled = true;
          } else {
            if ($this->mollomCheck->verifyKey()) {
              $this->mollomEnabled = true;
              $this->setCache('mollomKeyValid','YES');
            } else {
              $this->setCache('mollomKeyValid','NO');
            }
          }
        } catch (Exception $e) {
          $this->dbg('Mollon exception: '.$e->getMessage());
          $this->mollomEnabled = false;
        }
      } else {
        $this->dbg('mollom class not found');
      }
    } else {
      $this->dbg('mollom not enabled');
    }

    $now = gettimeofday();
    $this->startTime = $now['sec'] * 1000000 + $now['usec'];
  }

  /**
   * setLogRoot - specify where to write logfiles
   *
   * @param string $dir - directory where to write to, defaults to /var/log/botbouncer
   * @return bool - true is successful
   */

  public function setLogRoot ($dir) {
    if (!empty($dir) && is_writable($dir)) {
      $this->logRoot = $dir;
      $this->dbg('Logging to '.$dir);
      return true;
    } else {
      $this->dbg('Unable to write logs to '.$dir);
      return false;
    }
  }

  /** setMemcached
   *
   * use memCached server for caching
   *
   * @param string memCachedServer = server for memcache (use servername:port if port differs from default)
   * @return bool success
   */

  public function setMemcached($memCachedServer = '') {
    if (class_exists('Memcached') && !empty($memCachedServer)) {
      $this->memCached = new Memcached();
      if (strpos($memCachedServer,':') !== FALSE) {
        list($server,$port) = explode(':',$memCachedServer);
      } else {
        $server = $memCachedServer;
        $port = 11211;
      }
      $this->dbg('memcache: '.$server);
      return $this->memCached->addServer($server,$port);
    }
    return false;
  }

  private function dbg($msg) {
    if ($this->debugToLog) {
      $this->addLogEntry('fsc-debug.log',$msg);
    }

    if (!$this->debug) return;
    print $msg."\n";
  }

  /**
   * elapsed, a simple timer to monitor speed
   *
   * @return the number of microseconds used since instantiation
   */

  public function elapsed() {
    $now = gettimeofday();
    $end = $now['sec'] * 1000000 + $now['usec'];
    $elapsed = $end - $this->startTime;
    return $elapsed;
  }

  private function addLogEntry($logFile,$entry) {
    if (empty($this->logRoot)) return;
    if (!$this->logActivity) return;
    $logFile = basename($logFile,'.log');
    if (!is_writable($this->logRoot)) {
      return;
    }
    $ip = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : ' - ';
    if (isset($_SERVER['REQUEST_URI'])) {
      $logEntry = date('Y-m-d H:i:s').' '.$ip.' '.$_SERVER['REQUEST_URI'].' '.$entry;
    } else {
      $logEntry = date('Y-m-d H:i:s').' '.$ip.' - '.$entry;
    }
    file_put_contents($this->logRoot.'/'.$logFile.date('Y-m-d').'.log',$logEntry."\n",FILE_APPEND);
  }

  private function getCache($key) {
    if (!$this->memCached) return false;
    $val = $this->memCached->get($key);
    $this->dbg('CACHE: '.$key .' = '.$val);
    return $val;
  }

  private function setCache($key,$val,$expiry = 0) {
    if (!$this->memCached) return false;
    if (!$expiry) $expiry = 86400;
    return $this->memCached->set($key,$val,$expiry);
  }

  private function defaults($item) {
    switch ($item) {
      case 'ip': return $_SERVER['REMOTE_ADDR'];
      case 'email': return '';
      case 'username': return 'Anonymous';
      default: return '';
    }
  }

  private function setDefaults($data) {
    if (!isset($data['url'])) $data['url'] = '';
    if (!isset($data['content'])) $data['content'] = '';
    if (!isset($data['ips']) || !is_array($data['ips'])) $data['ips'] = array($this->defaults('ip'));
    return $data;
  }

  /**
   * honeypotCheck - verify IP using Honeypot project
   *
   * @param string $ip - IP address to check
   * @return bool - true is spam, false is ham
   *
   */

  public function honeypotCheck($ip) {
     if (!$this->doHpCheck) return;

    ## honeypot requests will be cached in DNS anyway
    $rev = array_reverse(explode('.', $ip));
    $lookup = $this->honeyPotApiKey.'.'.implode('.', $rev) . '.dnsbl.httpbl.org';

    $rev = gethostbyname($lookup);
    if ($lookup != $rev) {
      $this->matchedOn = 'ip';
      $this->addLogEntry('honeypot.log','SPAM '.$lookup.' '.$rev);
      $this->isSpam = true;
      return true;
    } else {
      $this->addLogEntry('honeypot.log','HAM '.$lookup.' '.$rev);
      return false;
    }
  }

  // Authenticates your Akismet API key
  private function akismet_verify_key() {
#    $this->dbg('akismet key check');

    if (empty($this->akismetApiKey)) {
      $this->dbg('No Akismet API Key');
      return false;
    }
    $cached = $this->getCache('akismetKeyValid');
    if (empty($cached)) {
      $request = array(
        'key'=> $this->akismetApiKey,
        'blog' => $this->akismetBlogURL
      );

      $keyValid = $this->doPOST('http://rest.akismet.com/1.1/verify-key',$request);
#      $this->addLogEntry('akismet.log','KEY CHECK: '.$keyValid.' http://rest.akismet.com/1.1/verify-key'.serialize($request));
      $this->setCache('akismetKeyValid',$keyValid);
    } else {
      $this->addLogEntry('akismet.log','KEY CHECK (cached) '.$cached);
      $this->dbg('akismet key (cached) '.$cached);
      $keyValid = $cached;
    }

    if ( 'valid' == $keyValid ) {
      $this->dbg('akismet key valid');
      return true;
    } else {
      $this->dbg('akismet key not valid');
      return false;
    }
  }


  /**
   * mollomCheck - check data against mollom
   *
   * @param array $data - associative array with data to use for checking
   *
   * @return bool: true is spam, false is ham
   */

  public function mollomCheck($data) {
    if (!$this->mollomEnabled) return false;
    $this->dbg('mollom check');
    $data = $this->setDefaults($data);
    $cached = $this->getCache('mollom'.md5(serialize($data)));
    if (!empty($cached)) {
      $isSpam = $cached;
      $data['fromcache'] = '(cached)'; // for logging
    } else {
      try {
        $isSpam = $this->mollomCheck->checkContent(
          '', # sessionID
          '', # $postTitle
          $data['content'], # $postBody
          $data['username'], # $authorName
          $data['url'], # $authorUrl
          $data['email'], # authorEmail
          '', # $authorOpenId
          '', # $authorId
          $data['ips'] ## added to mollom.php class for commandline processing
        );
        $this->setCache('mollom'.md5(serialize($data)),$isSpam);
        $data['fromcache'] = '';
      } catch (Exception $e) {
        $this->dbg('Exception thrown '.$e->getMessage());
        $isSpam = array('spam'=> 'exception');
      }
    }

    if ($isSpam['spam'] == 'spam') {
      $this->dbg('mollom check SPAM');
      $this->matchedOn = 'unknown';
      $this->addLogEntry('mollom.log',$data['fromcache'].' SPAM '.$data['username'].' '.$data['email'].' '.join(',',$data['ips']));
      $this->isSpam = true;
      return true;
    } else {
      ## mollom has state "unsure" as well, but let's just take that as HAM for now
      $this->dbg('mollom check HAM');
      $this->addLogEntry('mollom.log',$data['fromcache'].' HAM '.$data['username'].' '.$data['email'].' '.join(',',$data['ips']));
      return false;
    }
  }

  /**
   * akismetCheck - check data against akismet
   *
   * @param array $data - associative array with data to use for checking
   *
   * possible keys for data (all optional): blog, user_ip, user_agent, referrer, permalink, comment_type, comment_author, comment_author_email, comment_author_url, comment_content
   *
   * @return bool: true is spam, false is ham
   */

  public function akismetCheck($data) {
    if (!$this->akismetEnabled) return false;
    if (!$this->akismet_verify_key()) return false;
    $this->dbg('akismet check');
    if (!is_array($data['ips'])) $data['ips'] = array();

    ## set some values the way akismet expects them
    $data['user_ip'] = !empty($data['ips'][0]) ? $data['ips'][0]: $this->defaults('ip'); ## akismet only handles one IP, so take the first
    $data['comment_author'] = !empty($data['username']) ? $data['username'] : $this->defaults('username');
    $data['comment_author_email'] = !empty($data['email']) ? $data['email'] : $this->defaults('email');
    $data['comment_content'] = !empty($data['content']) ? $data['content'] : $this->defaults('content');

    foreach ($this->akismetFields as $field) {
      if (!isset($data[$field])) {
        switch ($field) {
          ## set some defaults that will probably return Ham
          case 'blog': $data['blog'] = $this->akismetBlogURL;break;
          case 'user_ip': $data['user_ip'] = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR']:'';break;
          case 'user_agent': $data['user_agent'] = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT']:'';break;
          case 'referrer': $data['referrer'] = isset($_SERVER['HTTP_REFERER']) ? $_SERVER['HTTP_REFERER']:'http://www.wordpress.com';break;
          case 'permalink': $data['permalink'] = '';break;
          case 'comment_type': $data['comment_type'] = 'comment';break;
          case 'comment_author': $data['comment_author'] = 'Admin';break;
          case 'comment_author_email': $data['comment_author_email'] = 'botbouncer@gmail.com';break;
          case 'comment_author_url': $data['comment_author_url'] = '';break;
          case 'comment_content': $data['comment_content'] = '';break;
        }
      }
    }

    $cached = $this->getCache('akismet'.md5(serialize($data)));
    if (!empty($cached)) {
      $isSpam = $cached;
      $data['fromcache'] = '(cached)'; // for logging
    } else {
      $isSpam = $this->doPOST('http://'.$this->akismetApiKey.'.rest.akismet.com/1.1/comment-check',$data);
      $this->setCache('akismet'.md5(serialize($data)),$isSpam);
      $data['fromcache'] = '';
    }

    if ( 'true' == $isSpam ) {
      $this->dbg('akismet check SPAM');
      $this->matchedOn = 'unknown';
      $this->addLogEntry('akismet.log',$data['fromcache'].' SPAM '.$data['username'].' '.$data['email'].' '.join(',',$data['ips']));
      $this->isSpam = true;
      return true;
    } else {
      $this->dbg('akismet check HAM');
      $this->addLogEntry('akismet.log',$data['fromcache'].' HAM '.$data['username'].' '.$data['email'].' '.join(',',$data['ips']));
      return false;
    }
  }

  /**
   * doPOST - run a POST request to some URL and return the result
   */
  private function doPOST($url,$requestdata = array()) {
    $date = date('r');

    $requestheader = array(
      'Host: '.parse_url($url,PHP_URL_HOST),
      'Content-Type: application/x-www-form-urlencoded',
      'Date: '. $date,
    );
    $data = '';
    foreach ($requestdata as $param => $value) {
      if (!is_array($value)) {
        $data .= $param.'='.urlencode($value).'&';
      } // else -> forget about arrays for now
    }
    $data = substr($data,0,-1);
    $requestheader[] = 'Content-Length: '.strlen($data);

    $header = '';
    foreach ($requestheader as $param) {
      $header .= $param.$this->LE;
    }

    $curl = curl_init();
    curl_setopt($curl, CURLOPT_URL, $url);
    curl_setopt($curl, CURLOPT_TIMEOUT, 30);
    curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, FALSE);
    curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, FALSE);
    curl_setopt($curl, CURLOPT_HTTPHEADER,$requestheader);
    curl_setopt($curl, CURLOPT_DNS_USE_GLOBAL_CACHE, TRUE);
    curl_setopt($curl, CURLOPT_USERAGENT,$this->UA);
    curl_setopt($curl, CURLOPT_POST, 1);

    curl_setopt($curl, CURLOPT_POSTFIELDS, $data);

    $result = curl_exec($curl);
    $status = curl_getinfo($curl,CURLINFO_HTTP_CODE);
    if ($status != 200) {
      $error = curl_error($curl);
      $this->dbg('Curl Error '.$status.' '.$error);
    }
    curl_close($curl);
    return $result;
  }

  /**
   * doGET - run a GET request to some URL and return the result
   */

  private function doGET($cUrl) {
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $cUrl);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    $result = curl_exec($ch);
    return $result;
  }


  /** setSFSSpamTriggers - set StopForumSpam triggers, if you want to be more specific on the triggers
   *
   * @param array $triggers array with details for SFS triggers
   *
   * defaults to:
   *
   * array (
   *
   *  'username' => array (               // ban on username
   *
   *    'ban_end' => FALSE,               // Permanent ban
   *
   *    'freq_tolerance' => 2,            // allow when 2 or less in the frequency API field
   *
   *    'ban_reason' => 'Error processing data, please try again', ## let's not make them any wiser
   *
   *   ),
   *
   *  'email' => array (                  // ban on email
   *
   *    'ban_end' => FALSE,               // Permanent ban
   *
   *    'freq_tolerance' => 0,
   *
   *    'ban_reason' => 'Error processing data, please try again', ## let's not make them any wiser
   *
   *  ),
   *
   *  'ip' => array (                     // ban on ip address
   *
   *    'ban_end' => 630000,              // 60*60*24*7 ban for 7 days
   *
   *    'freq_tolerance' => 1,
   *
   *    'ban_reason' => 'Error processing data, please try again', ## let's not make them any wiser
   *
   *  )
   *
   *);
   *
   *
   * @returns null
   *
  */


  public function setSFSSpamTriggers($triggers = array()) {
    if (sizeof($triggers)) {
      $this->spamTriggers = $triggers;
    }
  }

  /**
   * stopForumSpamCheck - check using the SFS API
   *
   * @param array $data - array containing data to check
   *
   * needs to contain at least one of
   *
   * $data['username'] - (string) username to check
   *
   * $data['ips'] - (array) list of IPs to check
   *
   * $data['email'] - (string) email to check
   *
   * @return integer - number of times something was matched
   *
   */

  function stopForumSpamCheck($data = array()) {
    if (!sizeof($data['ips']) && isset($_SERVER['REMOTE_ADDR'])) {
      $data['ips'][] = $_SERVER['REMOTE_ADDR'];
      if (isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $data['ips'][] = $_SERVER['HTTP_X_FORWARDED_FOR'];
      }
    }

    $isSfsSpam = 0;
    $this->dbg('SFS check');

    $spamTriggers = $this->sfsSpamTriggers;
    if (empty($data['username'])) {
      unset($spamTriggers['username']);
    } else {
      $spamTriggers['username']['value'] = $data['username'];
    }
    if (empty($data['ips'])) {
      unset($spamTriggers['ip']);
    } else {
      $spamTriggers['ip']['value'] = $data['ips'];
    }
    if (empty($data['email'])) {
      unset($spamTriggers['email']);
    } else {
      $spamTriggers['email']['value'] = $data['email'];
    }

    $apiRequest = '';
    foreach ($spamTriggers as $trigger => $banDetails) {
      if (!empty($banDetails['value'])) {
        if (is_array($banDetails['value'])) {
          foreach ($banDetails['value'] as $v) {
            $apiRequest .= $trigger.'[]='.urlencode($v).'&';
          }
        } else {
          $apiRequest .= $trigger.'[]='.urlencode($banDetails['value']).'&';
        }
      }
    }

    $cached = $this->getCache('SFS'.$apiRequest);
    if (!$cached) {
      $cUrl = $this->stopSpamAPIUrl.'?'.$apiRequest.'xmldom&unix';
      $this->addLogEntry('sfs-apicall.log',$cUrl);
      $xml = $this->doGET($cUrl);

      if (!$xml) {
        $this->addLogEntry('sfs-apicall.log','FAIL ON XML');
        return false;
      }
      $this->setCache('SFS'.$apiRequest,$xml);
      $cached = ''; // for logging
    } else {
      $xml = $cached;
      $cached = '(cached)'; // for logging
    }
    ## the resulting XML is an
    $response = simplexml_load_string($xml);

  #  var_dump($response);exit;
    $spamMatched = array();
    if ($response->success) {
      $muninEntry = '';
      foreach ($spamTriggers as $trigger => $banDetails) {
        ## iterate over the results found, eg email, ip and username
        foreach ($response->$trigger as $resultEntry) {
          if ($resultEntry->appears) {
         #   var_dump($resultEntry);
            if (
              (
              ## there's a ban end check if it's still in range
              (!empty($banDetails['ban_end']) && $resultEntry->lastseen+$banDetails['ban_end'] > time())
              ## or the ban is permanent
              || empty($banDetails['ban_end'])) &&
              ## check if the frequency is in range
              ((int)$resultEntry->frequency > $banDetails['freq_tolerance'])
            ) {
              $isSfsSpam++;
              $banDetails['matchedon'] = $trigger;
              $this->matchedOn .= $trigger .';';
              $muninEntry .= ' SFSMATCH '.$trigger;
              $banDetails['matchedvalue'] = (string)$resultEntry->value;
              $banDetails['frequency'] = (string)$resultEntry->frequency;
              $spamMatched[] = $banDetails;
            }
          }
        }
      }
    }
    # var_dump($spamMatched);
    $this->matchDetails = $spamMatched;
    if ($isSfsSpam) {
      $this->dbg('SFS check SPAM');
      $this->addLogEntry('munin-graph.log',$muninEntry);
      $this->addLogEntry('sfs.log',$cached.' SPAM '.$data['username'].' '.$data['email'].' '.join(',',$data['ips']));
    } else {
      $this->dbg('SFS check HAM');
      $this->addLogEntry('sfs.log',$cached.' HAM '.$data['username'].' '.$data['email'].' '.join(',',$data['ips']));
    }
    $this->isSpam = $this->isSpam || $isSfsSpam > 0;
    return $isSfsSpam;
  }

  /**
   * ipIntelCheck - check with IP Intel Database API
   * @param string $ip -- IP to check.  If null, will try to pull from $_SERVER vars
   * @return boolean If within bad IP detection threshold.
   */
  function ipIntelCheck($ip) {

    if ((!isset($ip) || $ip == "") && isset($_SERVER['REMOTE_ADDR'])) {
      $ip = $_SERVER['REMOTE_ADDR'];
      if (isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
      }
    }

    $this->dbg('IPI check');
    $this->addLogEntry('ipi-apicall.log','IPI Check on ' . $ip);

    $resultNumeric = null;
    $cached = $this->getCache('IPI'.$ip);
    if (!$cached) {
      $cUrl = $this->ipIntelAPIUrl . '?ip=' . urlencode($ip) . '&contact=' . urlencode($this->ipIntelContact);
      $this->addLogEntry('ipi-apicall.log',$cUrl);
      $resultString = $this->doGET($cUrl);

      if (!is_numeric($resultString))
      {
        $this->addLogEntry('ipi-apicall.log','API returned non-number');
        return false;
      }

      $resultNumeric = (float) $resultString;

      if ($resultNumeric < 0) {
        $this->addLogEntry('ipi-apicall.log','API returned error code: ' . $resultNumeric);
        return false;
      }

      $this->setCache('IPI'.$ip,$resultNumeric);
      $cached = ''; // for logging
    } else {
      $resultNumeric = $cached;
      $cached = '(cached)'; // for logging
    }

    if (is_null($resultNumeric) || $resultNumeric < 0 || $resultNumeric > 1)
    {
        $this->addLogEntry('ipi-apicall.log','API or cache returned out of bounds result: ' . $resultNumeric);
        return false;
    }

    if ($resultNumeric > $this->ipIntelSpamThreshold)
    {
        $this->dbg('SFS check SPAM');
        $this->addLogEntry('ipi-apicall.log','SPAM IP detected: ' . $ip . ' --- score is: ' . $resultNumeric);
        return true;
    }
      return false;
  }


  /**
   * isSpam - match submission against spam protection sources
   * @param array $data - array containing information
   * structure:
   *
   *    $data['email'] = (string) email address
   *
   *    $data['username'] = (string) username
   *
   *    $data['ips'] = array ('ip1','ip2')
   *
   *    $data['user_agent'] = (string) Browser Agent
   *
   *    $data['referrer'] = (string) referring URL
   *
   *    $data['content'] = (string) Other content
   *
   * @param bool $checkAll - continue checking other services
   *
   *  true - check against all services
   *
   *  false - only check next service if previous one returned ham
   *
   * @return integer - number of services that returned "spam" status. If checkAll is false will be 0 or 1
   */

  function isSpam($data,$checkAll = false) {
    $this->dbg('isSpam call');
    ## for external functionality testing, allow "test=ham" or "test=spam"
    if (isset($data['test'])) {
      if ($data['test'] == 'ham') {
        $this->matchedBy = 'HAM test';
        return false;
      } elseif ($data['test'] == 'spam') {
        $this->matchedBy = 'SPAM test';
        return true;
      }
    }
    $isSpam = 0;
    $servicesMatched = array();

    ## honeypot will be fastest
    if ($this->doHpCheck && !empty($data['ips'])) {
      $this->dbg('hpCheck');
      $isHP = false;
      foreach ($data['ips'] as $ip) {
        $this->dbg('hpCheck IP '.$ip);
        if ($this->honeypotCheck($ip)) {
          $this->dbg('hpCheck SPAM');
          $isHP = true;
          $this->matchedBy = 'Honeypot Project';
          $servicesMatched[] = 'HP';
          $isSpam++;
        }
      }
      if ($isHP) { ## make sure to only log once, if multiple IPs are checked
        $this->addLogEntry('munin-graph.log','HPSPAM');
      } else {
        $this->addLogEntry('munin-graph.log','HPHAM');
      }
    }
    if ((!$isSpam || $checkAll) && $this->sfsEnabled) {
      $num = $this->stopForumSpamCheck($data);
      if ($num) {
        $this->matchedBy = 'Stop Forum Spam';
        $this->dbg('SFS SPAM');
        $this->addLogEntry('munin-graph.log','SFSSPAM');
        $isSpam += $num;
        $servicesMatched[] = 'SFS';
      } else {
        $this->addLogEntry('munin-graph.log','SFSHAM');
      }
    }
    if ((!$isSpam || $checkAll) && $this->akismetEnabled) {
      if ($this->akismetCheck($data)) {
        $this->dbg('Akismet SPAM');
        $this->matchedBy = 'Akismet';
        $servicesMatched[] = 'AKI';
        $isSpam++;
        $this->addLogEntry('munin-graph.log','AKISPAM');
      } else {
        $this->addLogEntry('munin-graph.log','AKIHAM');
      }
    }

    if ((!$isSpam || $checkAll) && $this->mollomEnabled) {
      if ($this->mollomCheck($data)) {
        $this->dbg('Mollom SPAM');
        $this->matchedBy = 'Mollom';
        $servicesMatched[] = 'MOL';
        $isSpam++;
        $this->addLogEntry('munin-graph.log','MOLSPAM');
      } else {
        $this->addLogEntry('munin-graph.log','MOLHAM');
      }
    }

    if ((!$isSpam || $checkAll) && $this->ipIntelEnabled) {

        $isIPIntelSpam = false;
        if (empty($data['ips']))
        {
            if ($this->ipIntelCheck('')) // Will attempt to use HTTP Headers
            {
                $isIPIntelSpam = true;
            }
        } else {
            foreach ($data['ips'] as $ip) {
                if ($this->ipIntelCheck($ip))
                {
                    $isIPIntelSpam = true;
                }
            }
        }

        if ($isIPIntelSpam)
        {
            $this->matchedBy = 'IP Intel';
            $servicesMatched[] = 'IPI';
            $isSpam++;
            $this->addLogEntry('munin-graph.log','IPISPAM');
        } else {
            $this->addLogEntry('munin-graph.log','IPIHAM');
        }
      }

    ## to test the comparison code below
/*
    $isSpam = 1;
    $servicesMatched = array_keys($this->services);
*/

    if ($isSpam) {
      ## Add a log to graph a comparison: a hit on SVC1 -> hit or miss in SVC2?
      foreach (array_keys($this->services) as $svcMain) {
        if (in_array($svcMain,$servicesMatched)) { ## hit on svcMain
          foreach (array_keys($this->services) as $svcCompare) {
            if ($svcCompare != $svcMain) { ## no need to compare with ourselves
              if (in_array($svcCompare,$servicesMatched)) {  ## also a hit on svcCompare
                $this->addLogEntry('munin-graph-compare.log',$svcMain.' - '.$svcCompare.' HIT ');
              } else {
                $this->addLogEntry('munin-graph-compare.log',$svcMain.' - '.$svcCompare.' MISS ');
              }
            }
          }
        }
      }
    }

    $this->dbg('overall SpamScore '.sprintf('%d',$isSpam));
    $this->isSpam = (bool) $isSpam > 0;
    if ($this->isSpam) {
      $this->addLogEntry('munin-graph.log','TOTAL LEVEL '.$isSpam);
    }
    $this->addLogEntry('munin-graph-timing.log',$this->elapsed());
    return $isSpam;
  }

} // eo class

