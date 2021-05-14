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
    
    #Function to generate registration/sign_in form.
    public function form(): string
    {
        #Open form
        $form = '<form role="form" id="signinup" name="signinup" autocomplete="on">';
        #Toggle for user login/registration/password reset
        $form .= '<div id="radio_signinup">
            <span>I am</span>
            <span class="radio_and_label">
                <input type="radio" id="radio_existuser" name="signinuptype" value="member" checked>
                <label for="radio_existuser">member</label>
            </span>
            <span class="radio_and_label">
                <input type="radio" id="radio_newuser" name="signinuptype" value="newuser">
                <label for="radio_newuser">new</label>
            </span>
            <span class="radio_and_label">
                <input type="radio" id="radio_forget" name="signinuptype" value="forget">
                <label for="radio_forget">forgetful</label>
            </span>
        </div>';
        #Email
        $form .= '<div class="float_label_div">
            <input form="signinup" type="email" required aria-required="true" name="email" id="signinup_email" placeholder="your@email.com" autocomplete="email" inputmode="email" maxlength="320" pattern="^[a-zA-Z0-9.!#$%&\'*+\/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$">
            <label for="signinup_email">your@email.com</label>
        </div>';
        #Password
        $form .= '<div class="float_label_div">
            <input form="signinup" type="password" required aria-required="true" name="password" id="signinup_password" placeholder="Password" autocomplete="current-password" inputmode="text" minlength="8">
            <label for="signinup_password">Password</label>
            <div class="showpassword" title="Show password"></div>
        </div>';
        #RememberMe checkbox
        $form .= '<div class="rememberme_div">
            <input role="checkbox" aria-checked="false" form="signinup" type="checkbox" name="rememberme" id="rememberme">
            <label for="rememberme">Remember me</label>
        </div>';
        #Submit button
        $form .= '<input role="button" form="signinup" type="submit" name="submit" id="signinup_submit" formaction="'.$_SERVER['REQUEST_URI'].'" formmethod="post" formtarget="_self" value="Sign in/Join">';
        #Close form
        $form .= '</form>';
        return $form;
    }
}
?>