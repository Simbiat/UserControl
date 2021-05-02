<?php
declare(strict_types=1);
namespace Simbiat\usercontrol;

class Security
{    
    #Attach common settings
    use \Simbiat\usercontrol\Settings;
    
    public function __construct()
    {
        #Cache DB controller, if not done already
        if (self::$dbcontroller === NULL) {
            self::$dbcontroller = new \Simbiat\Database\Controller;
        }
    }
    
    #Function to check whether IP is banned
    public function bannedIP(): bool
    {
        $ip = $this->getip();
        if ($ip === NULL) {
            #We failed to get any proper IP, something is definitely wrong, protect ourselves
            return true;
        }
        if (self::$dbcontroller->check('SELECT `ip` FROM `'.self::$dbprefix.'bannedip` WHERE `ip`=:ip', [':ip'=>$ip]) === true) {
            return true;
        } else {
            return false;
        }
    }
    
    #Function to return IP
    private function getip(): ?string
    {
        #Check if behind proxy
        if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            #Get list of known proxies. This is optional, but keeping a list may improve security somewhat
            $knownproxies = self::$dbcontroller->selectColumn('SELECT `ip` FROM `'.self::$dbprefix.'proxies`');
            #Get list of IPs
            #Logic based on https://raw.githubusercontent.com/zendframework/zend-http/master/src/PhpEnvironment/RemoteAddress.php
            $ips = array_diff(array_map('trim', explode(',', $_SERVER['HTTP_X_FORWARDED_FOR'])), $knownproxies);
            #Check if any are left
            if (!empty($ips)) {
                #Get the right-most IP
                $ip = filter_var(array_pop($ips), FILTER_VALIDATE_IP);
                if ($ip !== false) {
                    return $ip;
                }
            }
        }
        #Check if REMOTE_ADDR is set (it's more appropriate and secure to use it)
        if(!empty($_SERVER['REMOTE_ADDR'])) {
            $ip = filter_var($_SERVER['REMOTE_ADDR'], FILTER_VALIDATE_IP);
            if ($ip !== false) {
                return $ip;
            }
        }
        #Check if Client-IP is set. Can be easily spoofed, but it's not like we have a choice at this moment
        if(!empty($_SERVER['HTTP_CLIENT_IP'])) {
            $ip = filter_var($_SERVER['HTTP_CLIENT_IP'], FILTER_VALIDATE_IP);
            if ($ip !== false) {
                return $ip;
            }
        }
        return NULL;
    }
}
?>