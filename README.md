# CAPTCHA Plugin #

## Description ##

This plugin provides a CAPTCHA field on subscription forms using the 
<a href="https://www.phpcaptcha.org" target="_blank">Secureimage</a> package. 

## Installation ##

### Dependencies ###

Requires php version 5.4 or later and the php GD extension to be installed.

Requires the Securimage package to be installed.
Also requires Common Plugin to be installed,  see <https://github.com/bramley/phplist-plugin-common>

### Set the plugin directory ###
You can use a directory outside of the web root by changing the definition of `PLUGIN_ROOTDIR` in config.php.
The benefit of this is that plugins will not be affected when you upgrade phplist.

### Install through phplist ###
Install on the Plugins page (menu Config > Plugins) using the package URL
`https://github.com/bramley/phplist-plugin-captcha/archive/master.zip`

### Install Securimage ###
You also need to install the Securimage package from <https://www.phpcaptcha.org/download/>

Expand the zip file, then copy the securimage directory to your web site.

On the phplist Settings page, in the Captcha section, you must then specify the web path to the securimage directory.
For example, if you copied the Securimage package to the root of your web site then the path would be `/securimage`.

### Usage ###

For advice on configuring and using the plugin see the documentation page <https://resources.phplist.com/plugin/captcha>.

## Version history ##

    version         Description
    2.1.1+20180102  Update dependencies
    2.1.0+20161129  Allow captcha to be optionally included on each subscribe page
    2.0.1+20161014  Add dependencies
    2.0.0+20160419  Minor internal changes
    2014-06-29      Minor change
    2014-06-23      Released to GitHub
    2014-06-19      Initial version using Securimage, based on existing BotBouncer plugin
