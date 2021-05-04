<?php
declare(strict_types=1);
namespace Simbiat\usercontrol;

class Session implements \SessionHandlerInterface, \SessionIdInterface
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
    
    public function open($savePath, $sessionName)
    {
        if (self::$dbcontroller === NULL) {
            return false;
        } else {
            return true;
        }
    }
    
    public function close()
    {
        return true;
    }
    
    public function read($id): string
    {
        $session = self::$dbcontroller->selectRow('SELECT `data` FROM `'.self::$dbprefix.'sessions` WHERE `sessionid` = :id', array(':id'=>$id));
        if (empty($session)) {
            return '';
        } else {
            return $this->security->decrypt($session[0]['data']);
        }
    }
    
    public function write($id, $data): bool
    {
        $data = $this->security->encrypt($data);
        $bindings = array(':id'=>$id,':data'=>$data);
        $extrafields = '';
        $bindings[':viewing'] = rawurldecode($_SERVER['REQUEST_URI']);
        $extrafields .= ', `viewing`=:viewing';
        if (!isset($GLOBALS['twigparameters']['bot'])) {
            $bot = 0;
        } else {
            $bot = (int)$GLOBALS['twigparameters']['bot'];
            if ($bot !== 1 && $bot !== 0) {
                $bot = 0;
            }
        }
        if (!empty($GLOBALS['twigparameters']['botname'])) {
            $bindings[':username'] = $GLOBALS['twigparameters']['botname'];
            $extrafields .= ', `username`=:username';
        } else {
            if (!empty($_SESSION['username'])) {
                $bindings[':username'] = $_SESSION['username'];
                $extrafields .= ', `username`=:username';
            }
        }
        if (self::$dbcontroller->query('INSERT INTO `'.self::$dbprefix.'sessions` SET `sessionid`=:id, `bot`='.$bot.', `data`=:data'.$extrafields.' ON DUPLICATE KEY UPDATE `time`=UTC_TIMESTAMP(), `bot`='.$bot.', `data`=:data'.$extrafields, $bindings)) {
            return true;
        } else {
            return false;
        }
    }
    
    public function destroy($id): bool
    {
        if (self::$dbcontroller->query('DELETE FROM `'.self::$dbprefix.'sessions` WHERE `sessionid`=:id', array(':id'=>$id))) {
            return true;
        } else {
            return false;
        }
    }
    
    public function gc($maxlifetime): bool
    {
        if (self::$dbcontroller->query('DELETE FROM `'.self::$dbprefix.'sessions` WHERE `time` < FROM_UNIXTIME('.(time()-$this->sessionLife).')')) {
            return true;
        } else {
            return false;
        }
    }
    
    public function create_sid(): string
    {
        return session_create_id();
    }
}
?>