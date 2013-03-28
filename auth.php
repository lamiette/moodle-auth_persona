<?php

// This file is part of Moodle - http://moodle.org/
//
// Moodle is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Moodle is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Moodle.  If not, see <http://www.gnu.org/licenses/>.

/**
 * Authentication Plugin: Persona Authentication
 *
 * @package    auth
 * @subpackage persona
 * @copyright  2013 Catalyst IT <http://catalyst-eu.net>
 * @author     Stacey Walker <stacey@catalyst-eu.net>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

defined('MOODLE_INTERNAL') || die();

define('AUTH_PERSONA_OKAY', 'okay');

require_once($CFG->libdir.'/authlib.php');

/**
 * Persona authentication plugin.
 *
 * @package    auth
 * @subpackage persona
 * @copyright  2013 Catalyst IT <http://catalyst-eu.net>
 * @author     Stacey Walker <stacey@catalyst-eu.net>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class auth_plugin_persona extends auth_plugin_base {

    /**
     * The audience details for the plugin.
     * @var string
     */
    var $audience;

    /**
     * Constructor
     */
    function auth_plugin_persona() {
        global $CFG;
        $this->audience = $CFG->wwwroot;
        $this->authtype = 'persona';
        $this->config   = get_config('auth/persona');
    }

    /**
     * Returns true if the username and password work and false if they are
     * wrong or don't exist.
     *
     * @param string $username The username
     * @param string $password The password
     * @return bool Authentication success or failure.
     */
    function user_login($username, $password) {
        global $SESSION;
        if (!$username) {
            return false;
        }
        if (isset($SESSION) && isset($SESSION->auth_persona)) {
            $verification = current($SESSION->auth_persona);
            if ($verification->status === AUTH_PERSONA_OKAY) {
                $usernamestrip = str_replace('persona-user-', '', $username);
                if (md5($verification->email) == $usernamestrip) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Generate a unique username for the user based on
     * their email
     *
     * @param string $email from persona assertion and verification
     * @return string string plus md5 hash of email
     */
    protected function username($email) {
        return 'persona-user-' . md5($email);
    }


    /**
     * Returns true if this authentication plugin doesn't store
     * internal passwords.
     *
     * @return bool
     */
    function prevent_local_passwords() {
        return true;
    }

    /**
     * Returns true if this authentication plugin is 'internal'.
     *
     * @return bool
     */
    function is_internal() {
        return false;
    }

    /**
     * Returns true if this authentication plugin can change the
     * user's password.
     *
     * @return bool
     */
    function can_change_password() {
        return false;
    }

    /**
     * Returns the URL for changing the user's pw, or empty if the
     * default can be used.
     *
     * @return moodle_url
     */
    function change_password_url() {
        return null;
    }

    /**
     * Returns true if plugin allows resetting of internal password.
     *
     * @return bool
     */
    function can_reset_password() {
        return false;
    }

    /**
     * Verify that the given assertion with the persona.org verifier
     * and return the response to the loginpage_hook to create
     * form data for login submission hook.
     *
     * @param object $assertion the assertion sent from the persona login
     * @return object $response decoded response from the persona verification
     */
    protected function verify_assertion($assertion) {
        $postdata = 'assertion=' . urlencode($assertion) . '&audience=' . urlencode($this->audience);

        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, "https://verifier.login.persona.org/verify");
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $postdata);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
        $response = curl_exec($ch);
        curl_close($ch);

        return json_decode($response);
    }

    /**
     * Hook into the login page to create a form submission
     * based on the results from the persona.org assertion and
     * verification process.
     */
    function loginpage_hook() {
        global $frm, $SESSION;

        // Verify the assertion and set up the $frm data.
        $assertion = optional_param('personaassertion', null, PARAM_TEXT);
        if ($assertion) {
            $verified = $this->verify_assertion($assertion);
            if ($verified && ($verified->status === AUTH_PERSONA_OKAY)) {

                // Fake the user submitted form.
                $frm = new stdClass;
                $frm->username = $this->username($verified->email);
                $frm->password = null;

                // Add it to the SESSION for user_login purposes.
                $SESSION->auth_persona   = array();
                $SESSION->auth_persona[] = $verified;
            }
        }
        return;
    }

    /**
     * Add Javascript requirements where necessary to ensure
     * the persona.org logout can be called.
     */
    function logout_requirements() {
        global $PAGE, $USER;

        // Include the Persona modules for logout; only once per page.
        static $loaded = false;
        if (($USER->auth == $this->authtype) && !$loaded) {
            $PAGE->requires->js_module(array('name' => 'external-persona', 'fullpath' => new moodle_url('https://login.persona.org/include.js')));
            $PAGE->requires->yui_module('moodle-auth_persona-persona', 'M.auth_persona.init', array(array('user' => $USER->email)));
            $loaded = true;
        }
    }

    /**
     * Add the Javascript requirements for login via
     * persona.org authentication
     *
     * @param string $wantsurl URL to return to (not necessary here)
     * @return array $persona an array of details for the persona.org authentication link
     */
    function loginpage_idp_list($wantsurl) {
        global $PAGE;

        // Include the Persona
        $PAGE->requires->js_module(array('name' => 'external-persona', 'fullpath' => new moodle_url('https://login.persona.org/include.js')));
        $PAGE->requires->yui_module('moodle-auth_persona-persona', 'M.auth_persona.init');

        $persona = array(
            'url'  => new moodle_url('#'),
            'icon' => new pix_icon('persona_sign_in_black', get_string('auth_personasignin', 'auth_persona'), 'auth_persona', array('class' => 'auth-persona-loginbtn')),
            'name' => null
        );
        return array($persona);
    }
}
