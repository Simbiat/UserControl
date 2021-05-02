<?php
declare(strict_types=1);
namespace Simbiat\usercontrol;

trait Settings
{    
    #Database prefix
    static string $dbprefix = 'uc__';
    #Cached DB controller
    static ?\Simbiat\Database\Controller $dbcontroller = NULL;
}
?>