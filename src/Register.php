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
    
    #Function to generate registration form.
    public function form(): string
    {
        #Open form
        $form = '<form id="registration" name="registration" autocomplete="on">';
        #Username
        $form .= '<div class="float_label_div"><input form="registration" type="text" name="username" id="regform_username" placeholder="Username" autocomplete="username" inputmode="text" maxlength="64"><label for="regform_username">Username</label></div>';
        #Email
        $form .= '<div class="float_label_div"><input form="registration" type="email" required aria-required="true" name="email" id="regform_email" placeholder="your@email.com" autocomplete="email" inputmode="email" maxlength="320" pattern="^[a-zA-Z0-9.!#$%&\'*+\/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"><label for="regform_email">your@email.com</label></div>';
        #Optional telephone, if SMS are enabled
        if (self::$sms) {
            #Email
            $form .= '<div class="float_label_div"><input form="registration" type="tel" name="tel" id="regform_tel" placeholder="123456789012345" autocomplete="tel" inputmode="tel" maxlength="15" pattern="^[0-9]{6,15}$"><label for="regform_tel">Telephone</label></div>';
        }
        #Password
        $form .= '<div class="float_label_div"><input form="registration" type="password" required aria-required="true" name="password" id="regform_password" placeholder="Password" autocomplete="new-password" inputmode="text" minlength="8"><label for="regform_password">Password</label></div>';
        #RememberMe checkbox
        $form .= '<div class="rememberme_div"><input form="registration" type="checkbox" name="rememberme" id="reg_form_rememberme"><label for="reg_form_rememberme">Remember me</label></div>';
        #Submit button
        $form .= '<input form="registration" type="submit" name="submit" id="reg_form_submit" formaction="/uc/registration" formmethod="post" formtarget="_self" value="Register">';
        #Close form
        $form .= '</form>';
        return $form;
    }
}
?>