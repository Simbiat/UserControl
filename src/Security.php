<?php
declare(strict_types=1);
namespace Simbiat\usercontrol;

class Security
{    
    #Attach common settings
    use \Simbiat\usercontrol\Common;
    
    #Argon settings
    private array $argonSettings = [
        'memory_cost' => 1024,
        #Despite name, this is not time, but number of iterations
        'time_cost' => 2,
        'threads' => 2,
    ];
    #AES settings
    private array $aesSettings = [];
    
    public function __construct()
    {
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
        } else {
            #Generate the settings
            $this->argonSettings = (new \Simbiat\usercontrol\NoDB)->argonCalc();
        }
        #Load AES settings
        if (is_file(__DIR__.'/aes.json')) {
            #Read the file
            $aes = json_decode(file_get_contents(__DIR__.'/aes.json'), true);
            if (isset($aes['passphrase'])) {
                $this->aesSettings = $aes;
            } else {
                #Generate the settings
                $this->aesSettings = (new \Simbiat\usercontrol\NoDB)->genCrypto();
            }
        } else {
            #Generate the settings
            $this->aesSettings = (new \Simbiat\usercontrol\NoDB)->genCrypto();
        }
    }
    
    #Function to validate password
    public function passValid(int|string $id, string $password, string $hash): bool
    {
        #Cache DB controller, if not done already
        if (self::$dbcontroller === NULL) {
            self::$dbcontroller = new \Simbiat\Database\Controller;
        }
        #Validate password
        if (password_verify($password, $hash)) {
            #Check if it needs rehashing
            if (password_needs_rehash($hash, PASSWORD_ARGON2ID, $this->argonSettings)) {
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
        return password_hash($password, PASSWORD_ARGON2ID, $this->argonSettings);
    }
    
    #Function to encrypt stuff
    public function encrypt(string $data): string
    {
        if (empty($data)) {
            return '';
        }
        #Generate IV
        $iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length('AES-256-GCM'));
        #This is where tag will be written by OpenSSL
        $tag = '';
        #Ecnrypt and als get the tag
        $encrypted = openssl_encrypt($data, 'AES-256-GCM', hex2bin($this->aesSettings['passphrase']), OPENSSL_RAW_DATA, $iv, $tag, '', 16);
        #Ecnrypt and prepend IV and tag
        return base64_encode($iv.$tag.$encrypted);
    }
    
    #Function to decrypt stuff
    public function decrypt(string $data): string
    {
        if (empty($data)) {
            return '';
        }
        #Decode
        $data = base64_decode($data);
        #Get IV
        $iv = substr($data, 0, 12);
        #Get tag
        $tag = substr($data, 12, 16);
        #Strip them from data
        $data = substr($data, 28);
        return openssl_decrypt($data, 'AES-256-GCM', hex2bin($this->aesSettings['passphrase']), OPENSSL_RAW_DATA, $iv, $tag);
    }
}
?>