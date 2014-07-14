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
 *
 * Authentication plugin: Two-factor Authentication
 *
 * Standard authentication function.
 *
 * @package     auth_twofac
 * @author      Marcus Boon<marcus@catalyst-au.net>
 * @license     http://www.gnu.org/copyleft/gpl.html GNU Public License
 */

if (!defined('MOODLE_INTERNAL')) {
    die('Direct access to this script is forbidden.');
}

require_once($CFG->libdir.'/authlib.php');

/**
 * Two-factor authentication plugin
 */
class auth_plugin_twofac extends auth_plugin_base {

    /**
     * Constructor.
     */
    public function __construct() {

        $this->authtype = 'twofac';
        $this->config   = get_config('auth/twofac');
    }

    /**
     * Returns true if the username and password work, false otherwise
     * or it does not exist.
     *
     * @param string $username The username
     * @param string $password The password
     *
     * @return bool Authentication success or failure
     */
    public function user_login($username, $password) {
        global $CFG, $DB;

        $user = $DB->get_record(
            'user',
            array(
                'username' => $username,
                'mnethostid' => $CFG->mnet_localhost_id
            )
        );

        if ($user) {
            return validate_internal_user_password($user, $password);
        }

        return false;
    }

    /**
     * Updates the user's password.
     *
     * Called when the user pasword is updated.
     *
     * @param object $user User table object
     * @param string $newpassword Plaintext password
     *
     * @return bool
     */
    public function user_update_password($user, $newpassword) {

        $user = get_complete_user_data('id', $user->id);
        return update_internal_user_password($user, $newpassword);
    }

    /**
     * Overwrite the post login hook
     *
     * @param &$user Pointer to user object
     * @param $username This is the username
     * @param $password THis is the password
     *
     * @return void
     */
    public function user_authenticated_hook(&$user, $username, $password) {
    }
}
