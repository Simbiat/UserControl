//Regex for proper email
var emailRegex = '[a-zA-Z0-9.!#$%&\'*+\/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*';

//Show or hide password. Should be attached to .showpassword class to "mousedown" event
function showPassToggle()
{
    //Prevent focus stealing
    event.preventDefault();
    var eyeIcon = event.target;
    var passField = eyeIcon.parentElement.getElementsByTagName('input').item(0);
    if (passField.type === 'password') {
        passField.type = 'text';
        eyeIcon.title = 'Hide password';
    } else {
        passField.type = 'password';
        eyeIcon.title = 'Show password';
    }
}

//Password strength check. Purely as advise, nothing more.
function passwordStrengthOnEvent()
{
    //Attempt to get extra values to check against
    
    //Get element where we will be showing strength
    var strengthField = event.target.parentElement.querySelectorAll('.password_strength').item(0);
    strengthField.innerHTML = passwordStrength(event.target.value);
}

//Actual check
function passwordStrength(password, extras = [])
{
    //Assing points for the password
    var points = 0;
    //Check that it's long enough
    if (/.{8,}/.test(password) === true) {
        points++;
    }
    //Add one more point, if it's twice as long as minimum requirement
    if (/.{16,}/.test(password) === true) {
        points++;
    }
    //Add one more point, if it's 3 times as long as minimum requirement
    if (/.{32,}/.test(password) === true) {
        points++;
    }
    //Add one more point, if it's 64 characters or more
    if (/.{64,}/.test(password) === true) {
        points++;
    }
    //Check for lower case letters
    if (/\p{Ll}/u.test(password) === true) {
        points++;
    }
    //Check for upper case letters
    if (/\p{Lu}/u.test(password) === true) {
        points++;
    }
    //Check for letters without case (glyphs)
    if (/\p{Lo}/u.test(password) === true) {
        points++;
    }
    //Check for numbers
    if (/\p{N}/u.test(password) === true) {
        points++;
    }
    //Check for punctuation
    if (/[\p{P}\p{S}]/u.test(password) === true) {
        points++;
    }
    //Reduce point for repeating characters
    if (/(.)\1{2,}/u.test(password) === true) {
        points--;
    }
    //Check against extra values. If password contains any of them - reduce points
    if (extras !== []) {
        
    }
    if (points <= 2) {
        return 'Weak';
    } else if (points = 5) {
        return 'Strong';
    } else if (points > 5 && points < 9) {
        return 'Very strong';
    } else if (points > 2 && points < 5) {
        return 'Medium';
    }
}

//Handle some adjustements when using radio-button switch
function loginRadioCheck()
{
    //Assign actual elements to variables
    var existUser = document.getElementById('radio_existuser');
    var newUser = document.getElementById('radio_newuser');
    var forget = document.getElementById('radio_forget');
    var login = document.getElementById('signinup_email');
    var password = document.getElementById('signinup_password');
    var button = document.getElementById('signinup_submit');
    //Adjust elements based on the toggle
    if (existUser.checked === true) {
        //Whether password field is required
        password.required = true;
        //Autocomplete suggestion for password
        password.setAttribute('autocomplete', 'current-password');
        //Autocomplete suggestion for login
        login.setAttribute('autocomplete', 'username');
        //Set pattern for login
        login.setAttribute('pattern', '^(.{1,64}|('+emailRegex+')$');
        //Enforce minimum length for password
        password.setAttribute('minlength', 8);
        //Adjust name of the button
        button.value = 'Sign in';
        //Add or remove listeners for password strength
        ['focus', 'change', 'input'].forEach(function(e) {
            password.removeEventListener(e, passwordStrengthOnEvent);
        });
    }
    if (newUser.checked === true) {
        password.required = true;
        password.setAttribute('autocomplete', 'new-password');
        login.setAttribute('autocomplete', 'email');
        login.setAttribute('pattern', '^'+emailRegex+'$');
        password.setAttribute('minlength', 8);
        button.value = 'Join';
        ['focus', 'change', 'input'].forEach(function(e) {
            password.addEventListener(e, passwordStrengthOnEvent);
        });
    }
    if (forget.checked === true) {
        password.required = false;
        password.removeAttribute('autocomplete');
        login.setAttribute('autocomplete', 'username');
        login.setAttribute('pattern', '^(.{1,64}|('+emailRegex+')$');
        password.removeAttribute('minlength');
        button.value = 'Remind';
        ['focus', 'change', 'input'].forEach(function(e) {
            password.removeEventListener(e, passwordStrengthOnEvent);
        });
    }
    //Adjust Aria values
    ariaNation(password);
}