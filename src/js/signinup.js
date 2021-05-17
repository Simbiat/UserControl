//Regex for proper email. This is NOT JS Regex, thus it has doubled slashes.
var emailRegex = '[a-zA-Z0-9.!#$%&\'*+\\/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*';
//Regex for username. This is NOT JS Regex, thus it has doubled slashes.
var userRegex = '[^\\/\\\\\\[\\]:;|=$%#@&\\(\\)\\{\\}!,+*?<>\\0\\t\\r\\n\\x00-\\x1F\\x7F\\x0b\\f\\x85\\v\\cY\\b]{1,64}';

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
    //Get strength 
    var strength = passwordStrength(event.target.value);
    //Set text
    strengthField.innerHTML = strength;
    //Remove classes
    strengthField.classList.remove('password_weak', 'password_medium', 'password_strong', 'password_very_strong');
    //Add class
    if (strength === 'very strong') {
        strengthField.classList.add('password_very_strong');
    } else {
        strengthField.classList.add('password_'+strength);
    }
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
    //Return value based on points. Note, that order is important.
    if (points <= 2) {
        return 'weak';
    } else if (2 < points && points < 5) {
        return 'medium';
    } else if (5 < points && points < 9) {
        return 'very strong';
    } else if (points = 5) {
        return 'strong';
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
    var rememberme = document.getElementById('rememberme');
    //Adjust elements based on the toggle
    if (existUser.checked === true) {
        //Whether password field is required
        password.required = true;
        //Autocomplete suggestion for password
        password.setAttribute('autocomplete', 'current-password');
        //Autocomplete suggestion for login
        login.setAttribute('autocomplete', 'username');
        //Set pattern for login
        login.setAttribute('pattern', '^('+userRegex+')|('+emailRegex+')$');
        //Enforce minimum length for password
        password.setAttribute('minlength', 8);
        //Adjust name of the button
        button.value = 'Sign in';
        //Add or remove listeners for password strength
        ['focus', 'change', 'input'].forEach(function(e) {
            password.removeEventListener(e, passwordStrengthOnEvent);
        });
        //Show or hide password field
        password.parentElement.classList.remove('hideme');
        //Show or hide remember me checkbox
        rememberme.parentElement.classList.remove('hideme');
        //Show or hide password requirements
        document.getElementById('password_req').classList.add('hideme');
        document.querySelectorAll('.pass_str_div').item(0).classList.add('hideme');
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
        password.parentElement.classList.remove('hideme');
        rememberme.parentElement.classList.remove('hideme');
        document.getElementById('password_req').classList.remove('hideme');
        document.querySelectorAll('.pass_str_div').item(0).classList.remove('hideme');
    }
    if (forget.checked === true) {
        password.required = false;
        password.removeAttribute('autocomplete');
        login.setAttribute('autocomplete', 'username');
        login.setAttribute('pattern', '^('+userRegex+')|('+emailRegex+')$');
        password.removeAttribute('minlength');
        button.value = 'Remind';
        ['focus', 'change', 'input'].forEach(function(e) {
            password.removeEventListener(e, passwordStrengthOnEvent);
        });
        password.parentElement.classList.add('hideme');
        rememberme.parentElement.classList.add('hideme');
        document.getElementById('password_req').classList.add('hideme');
        document.querySelectorAll('.pass_str_div').item(0).classList.add('hideme');
        //Additionally uncheck rememberme as precaution
        rememberme.checked = false;
    }
    //Adjust Aria values
    ariaNation(password);
}