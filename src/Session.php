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
        $session = self::$dbcontroller->selectValue('SELECT `data` FROM `'.self::$dbprefix.'sessions` WHERE `sessionid` = :id', [':id'=>$id]);
        if (empty($session)) {
            return '';
        } else {
            return $this->security->decrypt($session['data']);
        }
    }
    
    public function write(string $id, string $data): bool
    {
        #Check if bot
        $bot = $this->isBot();
        #Write data
        if (self::$dbcontroller->query(
            'INSERT INTO `'.self::$dbprefix.'sessions` SET `sessionid`=:id, `bot`=:bot, `data`=:data, `viewing`=:viewing, `username`=:username ON DUPLICATE KEY UPDATE `time`=UTC_TIMESTAMP(), `bot`=:bot, `data`=:data, `viewing`=:viewing, `username`=:username;',
            [
                ':id' => $id,
                ':data' => [
                    (empty($data) ? '' : $this->security->encrypt($data)),
                    'string',
                ],
                #What page is being viewed
                ':viewing' => rawurldecode((empty($_SERVER['REQUEST_URI']) ? 'index.php' : $_SERVER['REQUEST_URI'])),
                ':bot' => ($bot === false ? 0 : 1),
                ':username' => [
                    (empty($_SESSION['username']) ? ($bot === false ? NULL : $bot) : $_SESSION['username']),
                    (empty($_SESSION['username']) ? ($bot === false ? 'null' : 'string') : 'string'),
                ],
            ]
        )) {
            return true;
        } else {
            return false;
        }
    }
    
    public function destroy(string $id): bool
    {
        return self::$dbcontroller->query('DELETE FROM `'.self::$dbprefix.'sessions` WHERE `sessionid`=:id', [':id'=>$id]);
    }
    
    public function gc(int $maxlifetime): bool
    {
        if (self::$dbcontroller->query('DELETE FROM `'.self::$dbprefix.'sessions` WHERE `time` <= DATE_SUB(UTC_TIMESTAMP(), INTERVAL :life SECOND);', [':life' => [$this->sessionLife, 'int']])) {
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
    
    public function updateTimestamp(string $id, string $data): string
    {
        return self::$dbcontroller->query('UPDATE `'.self::$dbprefix.'sessions` SET `time`= UTC_TIMESTAMP() WHERE `sessionid` = :id;', [':id'=>$id]);
    }
    
    #Check if bot
    private function isBot(): bool|string
    {
        #Check if User Agent is present
        if (empty($_SERVER['HTTP_USER_AGENT'])) {
            return false;
        }
        #Initialize device detector
        $dd = (new \DeviceDetector\Parser\Bot());
        $dd->setUserAgent($_SERVER['HTTP_USER_AGENT']);
        $bot = $dd->parse();
        if ($bot === NULL) {
            #Not a bot
            return false;
        } else {
            #Bot
            return $bot['name'];
        }
    }
}
?>