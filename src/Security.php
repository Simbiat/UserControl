<?php
declare(strict_types=1);
namespace Simbiat\usercontrol;

class Security
{    
    #Attach common settings
    use \Simbiat\usercontrol\Common;
    
    #Argon version
    private $argonAlgo = PASSWORD_ARGON2ID;
    #Argon settings
    private array $argonSettings = [
        'memory_cost' => 1024,
        #Despite name, this is not time, but number of iterations
        'time_cost' => 2,
        'threads' => 2,
    ];
    
    public function __construct()
    {
        #Cache DB controller, if not done already
        if (self::$dbcontroller === NULL) {
            self::$dbcontroller = new \Simbiat\Database\Controller;
        }
        #Load Argon settings if argon.json exists
        if (is_file(__DIR__.'/argon.json')) {
            #Read the file
            $argon = json_decode(file_get_contents(__DIR__.'/argon.json'), true);
            #Update settings, if they are present and comply with minimum requirements
            if (isset($argon['memory_cost']) && $argon['memory_cost'] >= 1024) {
                $this->argonSettings['memory_cost'] = $argon['memory_cost'];
            }
            if (isset($argon['time_cost']) && $argon['time_cost'] >= 1) {
                $this->argonSettings['time_cost'] = $argon['time_cost'];
            }
            if (isset($argon['threads']) && $argon['threads'] >= 1) {
                $this->argonSettings['threads'] = $argon['threads'];
            }
        }
    }
    
    #Function to validate password
    public function passValid(int|string $id, string $password, string $hash): bool
    {
        #Validate password
        if (password_verify($password, $hash)) {
            #Check if it needs rehashing
            if (password_needs_rehash($hash, $this->argonAlgo, $this->argonSettings)) {
                #Rehash password and reset strieks (if any)
                self::$dbcontroller->query(
                    'UPDATE `'.self::$dbprefix.'users` SET `password`=:password, `strikes`=0 WHERE `userid`=:userid;',
                    [
                        ':userid' => [strval($id), 'string'],
                        ':password' => [$this->passHash($password), 'string'],
                    ]
                );
            } else {
                #Reset strikes (if any)
                self::$dbcontroller->query(
                    'UPDATE `'.self::$dbprefix.'users` SET `strikes`=0 WHERE `userid`=:userid;',
                    [
                        ':userid' => [strval($id), 'string']
                    ]
                );
            }
            return true;
        } else {
            #Increase strike count
            self::$dbcontroller->query(
                'UPDATE `'.self::$dbprefix.'users` SET `strikes`=`strikes`+1 WHERE `userid`=:userid',
                [':userid' => [strval($id), 'string']]);
            return false;
        }
    }
    
    #Function to hash password. Used mostly as a wrapper in case of future changes
    public function passHash(string $password): string
    {
        return password_hash($password, $this->argonAlgo, $this->argonSettings);
    }
}
?>