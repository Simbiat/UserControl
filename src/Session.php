<?php
declare(strict_types=1);
namespace Simbiat\usercontrol;

class Session implements \SessionHandlerInterface, \SessionIdInterface
{    
    #Attach common settings
    use \Simbiat\usercontrol\Common;
    
    public function __construct()
    {
        #Cache DB controller, if not done already
        if (self::$dbcontroller === NULL) {
            try {
                self::$dbcontroller = new \Simbiat\Database\Controller;
            } catch (\Exception $e) {
                #Do nothing, session will fail to be opened on `open` call
            }
        }
    }
}
?>