<?php
/**
 * Auth
 *
 * 認証、暗号化パッケージ
 *
 * @version    1.0
 * @author     Tomoo Kaku
 * @copyright  2013 Tomoo Kaku
 */

namespace Auth;

define('PASSPHASE1', 'secret-passphase1');      // private key passphase
define('PRIVATE_PEM', '/etc/private.pem');      // private key file path

/**
 * Auth login driver
 *
 * @subpackage  Auth
 */
class Auth
{
    /**
     * @var user when login succeeded
     */
    private $user = null;
    
    /**
     * Check for login
     *
     * @return  bool
     */
    private function perform_check()
    {
        // session start
        session_start();
        
        // fetch the uuid, user_id and login time from the session
        $uuid 	 = $_SESSION['uuid'];
        $user_id = $_SESSION['user_id'];
        $key	 = $_SESSION['key'];
        $time	 = $_SESSION['time'];
        
        // only worth checking.
        if (!empty($uuid) and !empty($user_id) and ! empty($key) and ! empty($time)) {
            return true;
        }
        
        return $this->force_login($uuid);
    }
    
    /**
     * Check the user exists
     *
     * @param   string $b
     * @return  bool
     */
    public function validate_user($b = '')
    {
        $b = trim($b) ?: trim($_REQUEST['b']);
        
        if (empty($b))
        {
            return false;
        }
        
        // Read Private Key (xxx.pem)
        $fp = fopen(PRIVATE_PEM, "r");
        $priv_key = fread($fp, 8192);
        fclose($fp);
        
        $res = openssl_get_privatekey($priv_key, PASSPHASE1);
        $data = "";
        openssl_private_decrypt(base64_decode($b), $data, $res, OPENSSL_PKCS1_PADDING);
        
        $b = $data;
        
        // $data = {"uuid":"<UUID>", "key":"<Common Key>", "time":"<UNIXTIME>"}
        $jsondata = json_decode($b, true);
        
        $uuid = $jsondata['uuid'];
        $key = (isset($jsondata['key'])) ? $jsondata['key'] : ''; // Get Common Key
        $time = $jsondata['time'];
        
        $user = $this->select_user($uuid);
        
        if (!$user) {
            $user = array('uuid' => $uuid);
        }
        
        $user['key'] = $key;
        $user['time'] = $time;
        
        return $user;
    }
    
    /**
     * login user
     *
     * @param   string $a
     * @param   string $b
     * @return  bool
     */
    public function login($a = '', $b = '')
    {
        if (!($this->user = $this->validate_user($a, $b)))
        {
            unset($_SESSION['user_id']);
            unset($_SESSION['uuid']);
            unset($_SESSION['key']);
            unset($_SESSION['time']);
            $_SESSION = array();
            return false;
        }
        
        if (empty($this->user['user_id']) || !$this->user['user_id']) {
            // new user >> create user
            $this->user['user_id'] = $this->create_user($this->user);
        }
        
        if (!$this->user['user_id']) {
            unset($_SESSION['user_id']);
            unset($_SESSION['uuid']);
            unset($_SESSION['key']);
            unset($_SESSION['time']);
            $_SESSION = array();
            return false;
        }
        
        // register so Auth::logout() can find us
        Auth::_register_verified($this);
        
        $_SESSION['user_id']  = $this->user['user_id'];
        $_SESSION['uuid']	 = $this->user['uuid'];
        $_SESSION['key']	  = $this->user['key'];
        $_SESSION['time']	 = $this->user['time'];
        
        return true;
    }
    
    /**
     * Force login user
     *
     * @param   string $uuid
     * @return  bool
     */
    public function force_login($uuid = '')
    {
        if (empty($uuid))
        {
            return false;
        }
        
        $this->user = $this->select_user($uuid);
        
        if ($this->user == false)
        {
            unset($_SESSION['user_id']);
            unset($_SESSION['uuid']);
            unset($_SESSION['key']);
            unset($_SESSION['time']);
            $_SESSION = array();
            return false;
        }
        
        $_SESSION['user_id'] = $this->user['user_id'];
        $_SESSION['uuid']    = $this->user['uuid'];
        $_SESSION['key']     = $this->user['key'];
        $_SESSION['time']    = $this->user['time'];
        
        return true;
    }
    
    /**
     * Logout user
     *
     * @return  bool
     */
    public function logout()
    {
        unset($_SESSION['user_id']);
        unset($_SESSION['uuid']);
        unset($_SESSION['key']);
        unset($_SESSION['time']);
        $_SESSION = array();
        return true;
    }
    
    /**
     * Create new user
     *
     * @param   Array $user
     * @return  string the user's ID
     */
    public function create_user($user = array())
    {
        if (empty($user['uuid']))
        {
            return false;
        }
        
        $id = $this->insert_user($user);
        
        if (!$id)
        {
            return false;
        }
        
        $user_id = $this->make_user_id($id);

        return $user_id;
    }
    
    /**
     * Get the device ID
     *
     * @return  string the device ID
     */
    public function get_uuid()
    {
        if (empty($this->user))
        {
            return false;
        }
        
        return $this->user['uuid'];
    }
    
    /**
     * Get the user's ID
     *
     * @return  string  the user's ID
     */
    public function get_user_id()
    {
        if (empty($this->user))
        {
            return false;
        }
        
        return $this->user['user_id'];
    }
    
    /**
     * Get the login time
     *
     * @return  string  login time
     */
    public function get_time()
    {
        if (empty($this->user))
        {
            return false;
        }
        
        return $this->user['time'];
    }

    /**
     * Get the Common Key
     *
     * @return  string  common keye
     */
    public function get_key()
    {
        if (empty($this->user))
        {
            return false;
        }
        
        return $this->user['key'];
    }
    
    /**
     * Check the request
     *
     * @param   string $a
     * @param   string $b
     * @return  bool
     */
    public function validate_request($a = '', $b = '')
    {
        $a = trim($a) ?: trim($_REQUEST['a']);
        $b = trim($b) ?: trim($_REQUEST['b']);
        
        if (empty($a) || empty($b))
        {
            return false;
        }
        
        $sercret_key = $_SESSION['key'];
        
        $data = mcrypt_decrypt(MCRYPT_RIJNDAEL_128, md5($sercret_key), base64_decode($a), MCRYPT_MODE_CBC, str_repeat("\0", 16));
        $padding = ord($data[strlen($data) - 1]);
        $a = substr($data, 0, -$padding);
        
        $uuid = $_SESSION['uuid'];
        
        $salt = $sercret_key . $a . $uuid;
        
        $data = mcrypt_decrypt(MCRYPT_RIJNDAEL_128, md5($salt), base64_decode($b), MCRYPT_MODE_CBC, str_repeat("\0", 16));
        $padding = ord($data[strlen($data) - 1]);
        $b = substr($data, 0, -$padding);
        
        $jsondata = json_decode($b, true);
        
        $time = $jsondata['time'];
        
        $jsondata['user_id'] = $_SESSION['user_id'];
        $jsondata['uuid']    = $_SESSION['uuid'];
        $jsondata['time']    = strval($time);
        
        return $jsondata;
    }
    
    /**
     * Make User's ID
     *
     * @param   number $id 
     * @return  Array user's Info.
     */
    private function make_user_id($id)
    {
        if (empty($this->user))
        {
            return false;
        }
        
        $last_login = time();
        $user_id = sha1($id.$last_login);
        
        $this->user['user_id'] = $user_id;

        $this->update_user($this->user);
        
        return $this->user;
    }
    
    /**
     * Make Crypt Response
     *
     * @param   string $data
     * @param   string $time
     * @return  Array  The Response
     */
    public function make_crypt_response($data, $time)
    {
        $a = strval($time);
        $b = $data;
        
        $jsondata = json_encode($data);
        
        $sercret_key = $_SESSION['key'];
        
        $uuid = $_SESSION['uuid'];
        
        $salt = md5($sercret_key . $a . $uuid);
        
        $padding = 16 - (strlen($a) % 16);
        $a .= str_repeat(chr($padding), $padding);
        
        $a = mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $salt, $a, MCRYPT_MODE_CBC, str_repeat("\0", 16));
        
        $a = base64_encode($a);
        
        $padding = 16 - (strlen($jsondata) % 16);
        $jsondata .= str_repeat(chr($padding), $padding);
        
        $jsondata = mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $salt2, $jsondata, MCRYPT_MODE_CBC, str_repeat("\0", 16));
        
        $b = base64_encode($jsondata);
        
        return array('a' => $a, 'b' => $b);
    }
    
    /**
     * select_user function.
     *
     * @access private
     * @param string $uuid
     * @return Array The User's Info.
     */
    private function select_user($uuid)
    {
        $mysqli = new mysqli("localhost", "root", "password", "auth_db");
        if (mysqli_connect_errno()) {
            return false;
        }
        
        if ($result = $mysqli->query("SELECT * FROM `user` WHERE `uuid` = '".$uuid."'")) {
            if ($row = mysqli_fetch_array($result)) {
                $user = array(
                    'uuid'       => $row['user_id'],
                    'time'       => $row['time'],
                    'login_date' => $row['login_date'],
                    'reg_date'   => $row['reg_date'],
                    'up_date'    => $row['up_date']
                );
            }
            
            $result->close();
        }
        
        $mysqli->close();
        
        return $user;
    }
    
    /**
     * insert_user function.
     *
     * @access private
     * @param Array $user
     * @return int ID 
     */
    private function insert_user($user)
    {
        $mysqli = new mysqli("localhost", "root", "password", "auth_db");
        if (mysqli_connect_errno()) {
            return false;
        }
        
        $result = $mysqli->query("INSERT INTO `user` (`uuid`, `time`, `user_id`) VALUES ('".$user['time']."', '".$user['user_id']."')");

        $id = false;

        if ($result) {
            $result = $mysqli->query("SELECT LAST_INSERT_ID() AS id FROM `user`");
            if ($result) {
                if ($row = $result->fetch_assoc()) {
                    $id = $row['id'];
                }
            }
        }

        $mysqli->close();
        
        return $id;
    }
    
    /**
     * update_user function.
     *
     * @access private
     * @param Array $user
     * @return bool 
     */
    private function update_user($user)
    {
        $mysqli = new mysqli("localhost", "root", "password", "auth_db");
        if (mysqli_connect_errno()) {
            return false;
        }
        
        $result = $mysqli->query("UPDATE `user` SET `time` = '".$user['time']."', `user_id` = '".$user['user_id']."'");

        $mysqli->close();
        
        return $result;
    }
    
    /**
     * delete_user function.
     *
     * @access private
     * @param string $user_id
     * @return bool
     */
    private function delete_user($user_id)
    {
        if (empty($user_id))
        {
            return false;
        }
        
        $mysqli = new mysqli("localhost", "root", "password", "auth_db");
        if (mysqli_connect_errno()) {
            return false;
        }
        
        $result = $mysqli->query("DELETE FROM `user` WHERE `user_id` = ".$user_id);

        $mysqli->close();
        
        return $relust;
    }
}

// end of file auth.php