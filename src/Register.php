<?php
declare(strict_types=1);
namespace Simbiat\usercontrol;

class Register
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
}
?>