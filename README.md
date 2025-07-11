# CAPTCHA Plugin #

## Description ##

This plugin provides a CAPTCHA field on subscription forms using the
<a href="https://github.com/dapphp/securimage" target="_blank">Secureimage</a> package.

## Installation ##

### Dependencies ###

Requires php version 5.4 or later and the php GD extension to be installed.

Requires the Securimage package to be installed.
Also requires Common Plugin to be installed. That is now included in phplist so you should only need to enable it.
See <https://github.com/bramley/phplist-plugin-common>

### Install through phplist ###
Install on the Plugins page (menu Config > Plugins) using the package URL
`https://github.com/bramley/phplist-plugin-captcha/archive/master.zip`

### Install Securimage ###
You also need to install the Securimage package from <https://github.com/dapphp/securimage/releases/tag/3.6.8>

Expand the zip file, then copy the securimage directory to your web site.

You need to make a small change to the securimage code which is explained on the documentation page
<https://resources.phplist.com/plugin/captcha#change_to_the_securimage_code>

On the phplist Settings page, in the Captcha section, you must then specify the web path to the securimage directory.
For example, if you copied the Securimage package to the root of your web site then the path would be `/securimage`.

### Usage ###

For advice on configuring and using the plugin see the documentation page <https://resources.phplist.com/plugin/captcha>.

## Version history ##

    version         Description
    2.4.1+20250711  Update URLs for Securimage
    2.4.0+20220810  Avoid displaying Captcha on preferences page
    2.3.0+20220625  Update the Botbouncer class
    2.2.3+20220310  Ensure that the response from stopforumspam is serialised as expected.
    2.2.2+20220220  Change default for "include on subscribe page" to be false
    2.2.1+20210428  Allow the plugin to be a dependency of phplist
    2.2.0+20210201  Add subscribe page option to not validate captcha for asubscribe
    2.1.4+20200712  Revise readme to explain the necessary change to securimage code
    2.1.3+20200515  Make the dependency check message clearer
    2.1.2+20200512  Update botbouncer class
    2.1.1+20180102  Update dependencies
    2.1.0+20161129  Allow captcha to be optionally included on each subscribe page
    2.0.1+20161014  Add dependencies
    2.0.0+20160419  Minor internal changes
    2014-06-29      Minor change
    2014-06-23      Released to GitHub
    2014-06-19      Initial version using Securimage, based on existing BotBouncer plugin
