<?php
declare(strict_types=1);
namespace Simbiat\usercontrol;

trait Common
{    
    #Database prefix
    public static string $dbprefix = 'uc__';
    #Flag for SEO statistics
    public static bool $SEOtracking = true;
    #Cached DB controller
    public static ?\Simbiat\Database\Controller $dbcontroller = NULL;
    
    #Function to log audit actions
    private function audit(int|string $id, string $action): void
    {
        self::$dbcontroller->query(
            'INSERT INTO `'.self::$dbprefix.'audit` (`userid`, `ip`, `useragent`, `action`) VALUES (:id, :ip, :ua, :action)',
            [
                ':id' => $id,
                ':ip' => $this->getip(),
                ':ua' => [
                    (empty($_SERVER['HTTP_USER_AGENT']) ? NULL : $_SERVER['HTTP_USER_AGENT']),
                    (empty($_SERVER['HTTP_USER_AGENT']) ? 'null' : 'string'),
                ],
                ':action' => $action,
            ]
        );
    }
    
    #Function to return IP
    public function getip(): ?string
    {
        #Check if behind proxy
        if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            #Get list of IPs, that do validate as proper IP
            $ips = array_filter(array_map('trim', explode(',', $_SERVER['HTTP_X_FORWARDED_FOR'])), function($value) {
                return filter_var($value, FILTER_VALIDATE_IP);
            });
            #Check if any are left
            if (!empty($ips)) {
                #Get the right-most IP
                return array_pop($ips);
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
    
    #Get Bot name, OS and Browser for user agent
    private function getUA(): ?array
    {
        #Check if User Agent is present
        if (empty($_SERVER['HTTP_USER_AGENT'])) {
            return NULL;
        }
        #Force full versions
        \DeviceDetector\Parser\Device\AbstractDeviceParser::setVersionTruncation(\DeviceDetector\Parser\Device\AbstractDeviceParser::VERSION_TRUNCATION_NONE);
        #Initialize device detector
        $dd = (new \DeviceDetector\DeviceDetector($_SERVER['HTTP_USER_AGENT']));
        $dd->parse();
        #Get bot name
        $bot = $dd->getBot();
        if ($bot !== NULL) {
            #Do not waste resources on bots
            return ['bot' => substr($bot['name'], 0, 64), 'os' => NULL, 'client' => NULL];
        }
        #Get OS
        $os = $dd->getOs();
        #Concat OS and version
        $os = trim(($os['name'] ?? '').' '.($os['version'] ?? ''));
        #Force OS to be NULL, if it's empty
        if (empty($os)) {
            $os = NULL;
        }
        #Get client
        $client = $dd->getClient();
        #Concat client and version
        $client = trim(($client['name'] ?? '').' '.($client['version'] ?? ''));
        #Force client to be NULL, if it's empty
        if (empty($client)) {
            $client = NULL;
        }
        return ['bot' => NULL, 'os' => substr($os, 0, 100), 'client' => substr($client, 0, 100)];
    }
}
?>