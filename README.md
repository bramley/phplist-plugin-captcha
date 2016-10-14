# CAPTCHA Plugin #

## Description ##

This plugin provides a CAPTCHA field on subscription forms using the 
<a href="https://www.phpcaptcha.org" target="_blank">Secureimage</a> package. 
The CAPTCHA requires that the user type the letters and digits of a distorted image. Securimage 
also provides a refresh button to display an alternative image, and an audio button to play a sound recording of the characters.

The plugin can also check subscription emails for spam using the Botbouncer class <https://github.com/michield/botbouncer>.
This currently uses only the Stop Forum Spam service to check email addresses, as that can be used without registering.
The other services supported by Botbouncer (Akismet, Project Honeypot, and Mollom) could be added if Stop Forum Spam 
proves not to be sufficient.


## Installation ##

### Dependencies ###

Requires php version 5.2 or later.

Requires the Securimage package to be installed.

### Set the plugin directory ###
You can use a directory outside of the web root by changing the definition of `PLUGIN_ROOTDIR` in config.php.
The benefit of this is that plugins will not be affected when you upgrade phplist.

### Install through phplist ###
Install on the Plugins page (menu Config > Plugins) using the package URL
`https://github.com/bramley/phplist-plugin-captcha/archive/master.zip`

In phplist releases 3.0.5 and earlier there is a bug that can cause a plugin to be incompletely installed on some
configurations (<https://mantis.phplist.com/view.php?id=16865>). The bug has been fixed in release 3.0.6.
Check that these files are in the plugin directory; if not then you will need to install manually.

* the file CaptchaPlugin.php
* the directory CaptchaPlugin

### Install manually ###
Download the plugin zip file from <https://github.com/bramley/phplist-plugin-captcha/archive/master.zip>

Expand the zip file, then copy the contents of the plugins directory to your phplist plugins directory.
This should contain

* the file CaptchaPlugin.php
* the directory CaptchaPlugin

### Install Securimage ###
You also need to install the Securimage package from <https://www.phpcaptcha.org/download/>

Expand the zip file, then copy the securimage directory to your web site.

On the phplist Settings page, in the Captcha section, you must then specify the web path to the securimage directory.
For example, if you copied the Securimage package to the root of your web site then the path would be `/securimage`.

###Settings###

On the Settings page you can specify:

* The path to the securimage directory on your web site (the default path is `/securimage`)
* Whether to validate the email address using the BotBouncer class (the default is yes)
* The prompt for the CAPTCHA field
* The message to be displayed to the subscriber when the entered CAPTCHA is incorrect
* The message to be displayed to the subscriber when the email address is rejected
* Whether to write a record to the event log for each incorrect CAPTCHA and subscription attempt
* Whether to send an email to the admin for each incorrect CAPTCHA and subscription attempt

### Internationalisation ###

If your subscribe pages are in a language other than English then on the Settings page you can change the prompt
and messages that are displayed to the subscriber to be in the local language.

Securimage supports a limited number of languages for the audio playback.
See <a href="https://www.phpcaptcha.org/documentation/audio-file-settings/#language">Changing language files</a>
for how to change the language.

###Test that it works###

On your phplist subscription page enter all of the mandatory fields and an incorrect value in the CAPTCHA field.
The subscription attempt should be rejected.

Go to <a href="http://www.stopforumspam.com/" target="_blank">Stop Forum Spam</a> and select an email address from the Hot Spam list.
Then try to subscribe to your lists using that email address. 

## Version history ##

    version         Description
    2.0.1+20161014  Add dependencies
    2.0.0+20160419  Minor internal changes
    2014-06-29      Minor change
    2014-06-23      Released to GitHub
    2014-06-19      Initial version using Securimage, based on existing BotBouncer plugin
