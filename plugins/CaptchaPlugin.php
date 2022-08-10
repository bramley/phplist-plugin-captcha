<?php
/**
 * CaptchaPlugin for phplist.
 *
 * This file is a part of CaptchaPlugin.
 *
 * @category  phplist
 *
 * @author    Duncan Cameron
 * @copyright 2011-2016 Duncan Cameron
 * @license   http://www.gnu.org/licenses/gpl.html GNU General Public License, Version 3
 */

/**
 * This class registers the plugin with phplist and hooks into the display and validation
 * of subscription pages.
 */
class CaptchaPlugin extends phplistPlugin
{
    const VERSION_FILE = 'version.txt';

    /*
     *  Inherited variables
     */
    public $name = 'Captcha Plugin';
    public $enabled = true;
    public $description = 'Creates a captcha field for subscription forms';
    public $documentationUrl = 'https://resources.phplist.com/plugin/captcha';
    public $authors = 'Duncan Cameron';
    public $settings = array(
        'captcha_securimage_path' => array(
            'description' => 'Path to the securimage directory (from the web root)',
            'type' => 'text',
            'value' => '/securimage',
            'allowempty' => false,
            'category' => 'Captcha',
        ),
        'captcha_bot_email' => array(
            'description' => 'Whether to validate the email address using bot bouncer',
            'type' => 'boolean',
            'value' => '1',
            'allowempty' => true,
            'category' => 'Captcha',
        ),
        'captcha_captcha_prompt' => array(
            'value' => 'Please enter the text in the CAPTCHA image',
            'description' => 'Prompt for the CAPTCHA field',
            'type' => 'text',
            'allowempty' => 0,
            'category' => 'Captcha',
        ),
        'captcha_captcha_message' => array(
            'value' => 'The CAPTCHA value that you entered was incorrect',
            'description' => 'Message to be displayed when entered CAPTCHA is incorrect',
            'type' => 'text',
            'allowempty' => 0,
            'category' => 'Captcha',
        ),
        'captcha_bot_message' => array(
            'value' => 'You cannot subscribe with this email address',
            'description' => 'Message to be displayed when email address is rejected',
            'type' => 'text',
            'allowempty' => 0,
            'category' => 'Captcha',
        ),
        'captcha_eventlog' => array(
            'description' => 'Whether to log event for each rejected captcha and each rejected subscription',
            'type' => 'boolean',
            'value' => '1',
            'allowempty' => true,
            'category' => 'Captcha',
        ),
        'captcha_copyadmin' => array(
            'description' => 'Whether to send an email to the admin for each rejected captcha and each rejected subscription',
            'type' => 'boolean',
            'value' => '0',
            'allowempty' => true,
            'category' => 'Captcha',
        ),
    );

    /*
     * Private functions
     */
    private function sendAdminEmail($text)
    {
        $body = <<<END
A subscription attempt has been rejected by the Captcha plugin.

$text
END;
        sendAdminCopy(s('subscription rejected by Captcha'), $body);
    }

    private function validateEmail($email)
    {
        global $tmpdir;

        require_once $this->coderoot . 'botbouncer.php';

        $bb = new Botbouncer();
        $bb->setLogRoot($tmpdir);
        $params = array(
            'email' => $email,
            'username' => '',
            'ips' => array(),
        );

        if (isset($_SERVER['REMOTE_ADDR'])) {
            $params['ips'] = array($_SERVER['REMOTE_ADDR']);
        }
        $isSpam = $bb->isSpam($params);

        if (!$isSpam) {
            return '';
        }
        $text = "spam subscription: $email $bb->matchedOn $bb->matchedBy";

        if (getConfig('captcha_eventlog')) {
            logEvent($text);
        }

        if (getConfig('captcha_copyadmin')) {
            $this->sendAdminEmail($text);
        }

        return getConfig('captcha_bot_message');
    }

    private function validateCaptcha($email, $captcha)
    {
        $securimage = new Securimage();

        if ($securimage->check($captcha)) {
            return '';
        }
        $text = "captcha verification failure: $email";

        if (getConfig('captcha_eventlog')) {
            logEvent($text);
        }

        if (getConfig('captcha_copyadmin')) {
            $this->sendAdminEmail($text);
        }

        return getConfig('captcha_captcha_message');
    }

    private function captchaEnabled()
    {
        $path = trim(getConfig('captcha_securimage_path'), '/');

        if (!file_exists($f = rtrim($_SERVER['DOCUMENT_ROOT'], '/') . "/$path/securimage.php")) {
            logEvent("securimage file '$f' not found");

            return false;
        }

        include_once $f;

        return true;
    }

    /*
     * Public functions
     */
    public function __construct()
    {
        $this->coderoot = dirname(__FILE__) . '/' . __CLASS__ . '/';
        $this->version = (is_file($f = $this->coderoot . self::VERSION_FILE))
            ? file_get_contents($f)
            : '';
        parent::__construct();
    }

    /**
     * Provide the dependencies for enabling this plugin.
     *
     * @return array
     */
    public function dependencyCheck()
    {
        return array(
            'GD extension installed' => extension_loaded('gd'),
            'curl extension installed' => extension_loaded('curl'),
            'Common Plugin must be enabled' => phpListPlugin::isEnabled('CommonPlugin'),
        );
    }

    public function adminmenu()
    {
        return array();
    }

    /**
     * Provide the captcha html to be included in a subscription page.
     *
     * @param array $pageData subscribe page fields
     * @param int   $userID   user id
     *
     * @return string
     */
    public function displaySubscriptionChoice($pageData, $userID = 0)
    {
        if ($_GET['p'] != 'subscribe') {
            return '';
        }

        if (empty($pageData['captcha_include']) || !$this->captchaEnabled()) {
            return '';
        }

        return Securimage::getCaptchaHtml(
            array(
                'input_text' => getConfig('captcha_captcha_prompt'),
            )
        );
    }

    /**
     * Provide additional validation when a subscribe page has been submitted.
     *
     * @param array $pageData subscribe page fields
     *
     * @return string an error message to be displayed or an empty string
     *                when validation is successful
     */
    public function validateSubscriptionPage($pageData)
    {
        if (empty($_POST)) {
            return '';
        }

        if ($_GET['p'] == 'asubscribe' && !empty($pageData['captcha_not_asubscribe'])) {
            return '';
        }

        if ($_GET['p'] == 'preferences') {
            return '';
        }

        if (!isset($_POST['email'])) {
            return '';
        }
        $email = $_POST['email'];

        if (!empty($pageData['captcha_include']) && $this->captchaEnabled()) {
            if (empty($_POST['captcha_code'])) {
                return getConfig('captcha_captcha_prompt');
            }

            if ($r = $this->validateCaptcha($email, $_POST['captcha_code'])) {
                return $r;
            }
        }

        if (getConfig('captcha_bot_email')) {
            if ($r = $this->validateEmail($email)) {
                return $r;
            }
        }

        return '';
    }

    /**
     * Provide html for the captcha options when editing a subscribe page.
     *
     * @param array $pageData subscribe page fields
     *
     * @return string additional html
     */
    public function displaySubscribepageEdit($pageData)
    {
        $include = isset($pageData['captcha_include']) ? (bool) $pageData['captcha_include'] : false;
        $notAsubscribe = isset($pageData['captcha_not_asubscribe']) ? (bool) $pageData['captcha_not_asubscribe'] : true;
        $html =
            CHtml::label(s('Include captcha in the subscribe page'), 'captcha_include')
            . CHtml::checkBox('captcha_include', $include, array('value' => 1, 'uncheckValue' => 0))
            . CHtml::label(s('Do not validate captcha for asubscribe'), 'captcha_not_asubscribe')
            . CHtml::checkBox('captcha_not_asubscribe', $notAsubscribe, array('value' => 1, 'uncheckValue' => 0));

        return $html;
    }

    /**
     * Save the captcha settings.
     *
     * @param int $id subscribe page id
     */
    public function processSubscribePageEdit($id)
    {
        global $tables;

        Sql_Query(
            sprintf('
                REPLACE INTO %s
                (id, name, data)
                VALUES
                (%d, "captcha_include", "%s"),
                (%d, "captcha_not_asubscribe", "%s")
                ',
                $tables['subscribepage_data'],
                $id,
                $_POST['captcha_include'],
                $id,
                $_POST['captcha_not_asubscribe']
            )
        );
    }
}
