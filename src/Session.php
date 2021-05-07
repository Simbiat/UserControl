<?php
declare(strict_types=1);
namespace Simbiat\usercontrol;

class Session implements \SessionHandlerInterface, \SessionIdInterface, \SessionUpdateTimestampHandlerInterface
{    
    #Attach common settings
    use \Simbiat\usercontrol\Common;
    
    #Default life time for session in seconds (5 minutes)
    private $sessionLife = 300;
    
    #Cache of security object
    private ?\Simbiat\usercontrol\Security $security = NULL;
    
    public function __construct(int $sessionLife = 300)
    {
        #Set serialization method
        ini_set('session.serialize_handler', 'php_serialize');
        #Dissallow permanent storage of session ID cookies
        ini_set('session.cookie_lifetime', '0');
        #ENforce use of cookies for session ID storage
        ini_set('session.use_cookies', 'On');
        ini_set('session.use_only_cookies', 'On');
        #Enforce strict mode to prevent an attacker initialized session ID of being used
        ini_set('session.use_strict_mode', 'On');
        #Enforce HTTP only to prevent JavaScript injection
        ini_set('session.cookie_httponly', 'On');
        #Allow session ID cookies only in case of HTTPS
        ini_set('session.cookie_secure', 'On');
        #Allow cookies only for same domain
        ini_set('session.cookie_samesite', 'Strict');
        #Set maximum life of session for garbage collector
        if ($sessionLife < 0) {
            $sessionLife = 300;
        }
        ini_set('session.gc_maxlifetime', strval($sessionLife));
        #Ensure that garbage collector is always triggered
        ini_set('session.gc_probability', '1');
        ini_set('session.gc_divisor', '1');
        $this->sessionLife = $sessionLife;
        #Disable transparent session ID management (life through URI values)
        ini_set('session.use_trans_sid', 'Off');
        #Set length of session IDs
        ini_set('session.hash_bits_per_character', '6');
        ini_set('session.sid_length', '256');
        #Set hash function
        ini_set('session.hash_function', 'sha3-512');
        #While we do not expect any files to be created, we change the default directory to the one which is not expected to be readable by the outside world
        ini_set('session.save_path', __DIR__.'/sessionsdata/');
        #Allow upload progress tracking
        ini_set('session.upload_progress.enabled', 'On');
        ini_set('session.upload_progress.cleanup', 'On');
        #Ensure session data is written only in case of changes (not likely to be affect anything in our case)
        ini_set('session.lazy_write', 'On');
        #Cache DB controller, if not done already
        if (self::$dbcontroller === NULL) {
            try {
                self::$dbcontroller = new \Simbiat\Database\Controller;
                $this->security = new \Simbiat\usercontrol\Security;
            } catch (\Exception $e) {
                #Do nothing, session will fail to be opened on `open` call
            }
        }
    }
    
    ##########################
    #\SessionHandlerInterface#
    ##########################
    public function open(string $path, string $name)
    {
        #If controller was initialized - session is ready
        if (self::$dbcontroller === NULL) {
            return false;
        } else {
            if (empty($_SESSION['UA'])) {
                #Add UserAgent data
                $_SESSION['UA'] = $this->getUA();
            }
            return true;
        }
    }
    
    public function close()
    {
        #No need to do anything at this point
        return true;
    }
    
    public function read(string $id): string
    {
        #Get session data
        $data = self::$dbcontroller->selectValue('SELECT `data` FROM `'.self::$dbprefix.'sessions` WHERE `sessionid` = :id', [':id'=>$id]);
        if (!empty($data)) {
            #Decrypt data
            $data = $this->security->decrypt($data);
            #Deserialize to check if UserAgent data is present
            $data = unserialize($data);
        }
        if (empty($data['UA'])) {
            #Add UserAgent data
            $data['UA'] = $this->getUA();
        }
        return serialize($data);
    }
    
    public function write(string $id, string $data): bool
    {
        #Deserialize to check if UserAgent data is present
        $data = unserialize($data);
        if (empty($data['UA'])) {
            #Add UserAgent data
            $data['UA'] = $this->getUA();
        }
        #Cache username (to prevent reading from Session)
        $username = ($data['UA']['bot'] !== NULL ? $data['UA']['bot'] : ($_SESSION['username'] ?? NULL));
        #Get IP
        $ip = $this->getip();
        #Prepare empty array
        $queries = [];
        #Update SEO related tables
        if (self::$SEOtracking === true && $data['UA']['bot'] === NULL && $ip !== NULL) {
            #Update unique visitors
            $queries[] = [
                'INSERT INTO `'.self::$dbprefix.'seo_visitors` SET `ip`=:ip, `os`=:os, `client`=:client ON DUPLICATE KEY UPDATE `views`=`views`+1;',
                [
                    #Data that makes this visitor unique
                    ':ip' => [$ip, 'string'],
                    ':os' => [
                        (empty($data['UA']['os']) ? '' : $data['UA']['os']),
                        'string',
                    ],
                    ':client' => [
                        (empty($data['UA']['client']) ? '' : $data['UA']['client']),
                        'string',
                    ],
                ],
            ];
            #Update page views
            $queries[] = [
                'INSERT INTO `'.self::$dbprefix.'seo_pageviews` SET `page`=:page, `referer`=:referer, `ip`=:ip, `os`=:os, `client`=:client ON DUPLICATE KEY UPDATE `views`=`views`+1;',
                [
                    #What page is being viewed
                    ':page' => rawurldecode((empty($_SERVER['REQUEST_URI']) ? 'index.php' : substr($_SERVER['REQUEST_URI'], 0, 256))),
                    #Optional refere (if sent from other sources)
                    ':referer' => [
                        (empty($_SERVER['HTTP_REFERER']) ? '' : substr($_SERVER['HTTP_REFERER'], 0, 256)),
                        'string',
                    ],
                    #Data that identify this visit as unique
                    ':ip' => [$ip, 'string'],
                    ':os' => [
                        (empty($data['UA']['os']) ? '' : $data['UA']['os']),
                        'string',
                    ],
                    ':client' => [
                        (empty($data['UA']['client']) ? '' : $data['UA']['client']),
                        'string',
                    ],
                ],
            ];
        }
        #Write session data
        $queries[] = [
            'INSERT INTO `'.self::$dbprefix.'sessions` SET `sessionid`=:id, `bot`=:bot, `ip`=:ip, `os`=:os, `client`=:client, `username`=:username, `page`=:page, `data`=:data ON DUPLICATE KEY UPDATE `time`=UTC_TIMESTAMP(), `bot`=:bot, `ip`=:ip, `os`=:os, `client`=:client, `username`=:username, `page`=:page, `data`=:data;',
            [
                ':id' => $id,
                #Whether this is a bot
                ':bot' => ($data['UA']['bot'] === NULL ? 0 : 1),
                ':ip' => [
                    (empty($ip) ? NULL : $ip),
                    (empty($ip) ? 'null' : 'string'),
                ],
                #Useragent details only for logged in users for ability of review of active sessions
                ':os' => [
                        (empty($data['UA']['os']) ? NULL : $data['UA']['os']),
                        (empty($data['UA']['os']) ? 'null' : 'string'),
                    ],
                    ':client' => [
                        (empty($data['UA']['client']) ? NULL : $data['UA']['client']),
                        (empty($data['UA']['client']) ? 'null' : 'string'),
                    ],
                #Either user name (if logged in) or bot name, if it's a bot
                ':username' => [
                    (empty($username) ? NULL : $username),
                    (empty($username) ? 'null' : 'string'),
                ],
                #What page is being viewed
                ':page' => rawurldecode((empty($_SERVER['REQUEST_URI']) ? 'index.php' : substr($_SERVER['REQUEST_URI'], 0, 256))),
                #Actual session data
                ':data' => [
                    (empty($data) ? '' : $this->security->encrypt(serialize($data))),
                    'string',
                ],
            ],
        ];
        return self::$dbcontroller->query($queries);
    }
    
    public function destroy(string $id): bool
    {
        return self::$dbcontroller->query('DELETE FROM `'.self::$dbprefix.'sessions` WHERE `sessionid`=:id', [':id'=>$id]);
    }
    
    public function gc(int $max_lifetime): bool
    {
        if (self::$dbcontroller->query('DELETE FROM `'.self::$dbprefix.'sessions` WHERE `time` <= DATE_SUB(UTC_TIMESTAMP(), INTERVAL :life SECOND);', [':life' => [$max_lifetime, 'int']])) {
            return true;
        } else {
            return false;
        }
    }
    
    #####################
    #\SessionIdInterface#
    #####################
    public function create_sid(): string
    {
        return session_create_id();
    }
    
    #########################################
    #\SessionUpdateTimestampHandlerInterface#
    #########################################
    public function validateId(string $id): bool
    {
        return self::$dbcontroller->check('SELECT `sessionid` FROM `'.self::$dbprefix.'sessions` WHERE `sessionid` = :id;', [':id'=>$id]);
    }
    
    public function updateTimestamp(string $id, string $data): bool
    {
        return self::$dbcontroller->query('UPDATE `'.self::$dbprefix.'sessions` SET `time`= UTC_TIMESTAMP() WHERE `sessionid` = :id;', [':id'=>$id]);
    }
}
?>