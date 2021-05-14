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