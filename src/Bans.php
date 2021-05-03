<?php
declare(strict_types=1);
namespace Simbiat\usercontrol;

class Bans
{    
    #Attach common settings
    use \Simbiat\usercontrol\Common;
    
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
        #Get IP
        $ip = $this->getip();
        if ($ip === NULL) {
            #We failed to get any proper IP, something is definitely wrong, protect ourselves
            return true;
        }
        #Check against DB table
        return self::$dbcontroller->check('SELECT `ip` FROM `'.self::$dbprefix.'bans_ips` WHERE `ip`=:ip', [':ip' => $ip]);
    }
    
    #Function to check whether name is banned
    public function bannedName(string $name): bool
    {
        #Check against DB table
        return self::$dbcontroller->check('SELECT `name` FROM `'.self::$dbprefix.'bans_names` WHERE `name`=:name', [':name' => $name]);
    }
    
    #Function to check whether email is banned
    public function bannedMail(string $mail): bool
    {
        #Validate that string is a mail
        if (filter_var($value, FILTER_VALIDATE_IP) === false) {
            #Not an email, something is wrong, protect ourselves
            return true;
        }
        #Check against DB table
        return self::$dbcontroller->check('SELECT `mail` FROM `'.self::$dbprefix.'bans_mails` WHERE `mail`=:mail', [':mail' => $mail]);
    }
}
?>