<?php
require_once('vendor/autoload.php');
use \Firebase\JWT\JWT;

date_default_timezone_set('Europe/Copenhagen');

//ini_set('display_errors', 1);
//ini_set('display_startup_errors', 1);
//error_reporting(E_ALL);

class Ssas {

    private static $mysqlServer = 'localhost';
    private static $mysqlUser = 'root';
    private static $mysqlPass = 'ssas';
    private static $mysqlDb = 'ssas';
    private static $key = "1bac7bc201c17b19e915760896f09cea48a089da5955a7205ba8f52b4fcdbd224cf4b01c22139e96e3d1838dd388ae821980e4bd02a6d4ce088b181b9edb0566";
    private static $data;
    private static $image_dir = "/var/www/html/uploads/";
    private $db;

    function __construct(){
        $this->db = new mysqli(self::$mysqlServer, self::$mysqlUser, self::$mysqlPass, self::$mysqlDb);
    }

    // This function will authenticate a user based on the token cookie.
    // returns true if the user is authenticated, otherwise return false
    // if the token is invalid or has expired the method will call exit() and not return anything
    function authenticate(){
        if(isset($_COOKIE['token'])) {
            try {
                //Retrieves the JWT token from the cookie
                $token = $_COOKIE['token'];

                //Decrypts the token. This call will throw an exception if the token is invalid
                $token = (array) JWT::decode($token,self::$key,array('HS512'));

                //Extracts the user data from the token
                self::$data = (array) $token['data'];

				//Check that the user actually exists (could have been removed)
				$uid = self::getUid();
				$uname = self::getUsername();
				if (self::verifyInput($uname)) {
                    $stmt = $this->db->prepare("SELECT id FROM user WHERE id = (?) AND username = (?);");
                    $stmt->bind_param("is", $uid, $uname);
                    $stmt->execute();
                    $result = $stmt->get_result();

					if (mysqli_num_rows($result) > 0) return true;
				}
				
                //If the query did not succeed, then there is something wrong!
                throw new Exception('Authentication failed!');

            } catch (Exception $e){

                //This will happend if
                //  1) The token has expired
                //  2) The token is not valid
                //  3) No user matching the user data exists

                self::logout();
                header("Location: index.php");
                exit(); //Just to be sure

            }
        }
       return false; //Could not authenticate
    }

    // This function will destroy the token cookie if it exists
    function logout(){
        if(isset($_COOKIE['token'])){
            unset($_COOKIE['token']);
            setcookie('token', '', time() - 3600);
        }
    }

    // This function will check if the user is logged in
    // If the user is not authenticated, the the method will try to authenticate.
    // returns true if the user is logged in otherwise false
    function isUserLoggedIn(){
        if(!isset(self::$data) && isset($_COOKIE['token'])) self::authenticate();
        return isset(self::$data);
    }

    // This function will return to logged in users id (if authenticated)
    function &getUid(){
        if(self::isUserLoggedIn()) return self::$data['uid'];
    }

    // This function will return to logged in users username (if authenticated)
    function &getUsername(){
        if(self::isUserLoggedIn()) return self::$data['username'];
    }

    // This function will create a new user with the given username password combo
    // returns true if the user was created, otherwise error message
    function createUser($username, $password){
        if($username == "") return "username can't be empty";
        if($password == "") return "password can't be empty";

		if (!(self::verifyInput($username) && self::verifyInput($password))) {
			// Bad user input, like illegal character/byte
			return "bad character";		
		}

        //Inserts username and password into the database
        $stmt = $this->db->prepare("INSERT INTO user(username,password) VALUES (?,?);");
        $un = $this->db->real_escape_string($username);
        $pw = $this->db->real_escape_string($password);
        $stmt->bind_param("ss", $un, $pw);
		$stmt->execute();

		//If exactly one row was affected then we know that the user was inserted.
		if (mysqli_affected_rows($this->db) == 1) return true;
        return "user could not be created";
    }

    // This function will login with the given username password combo
    // returns true if the login was successful, otherwise error message
    function login($username, $password) {

        //Query to get the username and real password,
        $stmt = $this->db->prepare("SELECT id,password FROM user WHERE username = (?);");
        $un = $un = $this->db->real_escape_string($username);
        $stmt->bind_param("s", $un);
        $stmt->execute();
		$result = $stmt->get_result();

		if (mysqli_num_rows($result) > 0) {
			$row = mysqli_fetch_assoc($result);
			$uid = $row['id'];
			$password_real = $row['password'];
        } else {
            return "username and password does not match";
        }

		// If the real password matches the one given, then the login succeeds.
        if(isset($password_real) && ($password === $password_real)){
            //Generates random tokenid
            //TODO Maybe store some of this server side... (Stateful or stateless?)
            $tokenId = base64_encode(mcrypt_create_iv(32, MCRYPT_DEV_URANDOM));

            $issuedAt = time(); //time of issue
            $notBefore = $issuedAt; //can be used to say that a token is not valid before a given time (not used)
            $expire = $notBefore + 3600 * 24 * 90; //token expires in 90 days
            $data = [
                'iat' => $issuedAt,
                'jti' => $tokenId,
                'nbf' => $notBefore,
                'exp' => $expire,
                'data' => [
                    'uid' => $uid,
                    'username' => $username
                ]
            ];

            //Computes the encrypted token
            $jwt = JWT::encode($data,self::$key,'HS512');

            //Sets to cookie to never expire as the token itself contains the expiration date (Mimimum exposure)
            setcookie("token", $jwt, -1);
            return true;
        } else return "username and password does not match";

        return "could not login";
    }

    // This function uploads the given image
    // returns true if the image was successfully uploaded, otherwise error message.
    function uploadImage($img){
        if(self::isUserLoggedIn()){
            $uid = self::getUid();
			$result = $this->db->query("INSERT INTO image(owner_id) VALUES(".$uid.");");
            if($result) {
				$iid = mysqli_insert_id($this->db);
				self::save_image($img, $iid);
				return true;
			}            
			return "Image could not be uploaded";
        }
        return "Image could not be uploaded2";
    }

    // This function will lookup a users id given the username
    // returns the user id if exists, otherwise false
    private function getUserId($username) {
        $stmt = $this->db->prepare("SELECT id FROM user WHERE username = (?);");
        $uname = $this->db->real_escape_string($username);
        $stmt->bind_param("s", $uname);
        $stmt->execute();
		$result = $stmt->get_result();
		if (mysqli_num_rows($result) > 0) {
			$row = mysqli_fetch_assoc($result);
			return $row['id'];
		}
        return false;
    }

    // This function will remove sharing with the given user for the given image
    // returns true if the operation was successful, otherwise false
    function removeShare($iid, $username){
        if(self::isUserLoggedIn() && self::isOwner($iid)){
            $uid = self::getUserId($username);
            if($uid == false) return false;

            //Removing sharing of image from database
            $stmt = $this->db->prepare("DELETE FROM shared_image WHERE image_id = (?) AND user_id = (?);");
            $stmt->bind_param("ii", $iid, $uid);
            $stmt->execute();

			return mysqli_affected_rows($this->db) == 1;
        }
        return false;
    }

    // This function will share the given image with the given user
    // returns true if the image was shared, otherwise false
    function shareImage($iid, $username)
    {
        //The user must be owner of the image to share it
        if(self::isUserLoggedIn() && self::isOwner($iid)) {

            //Getting uid from username
            $uid = self::getUserId($username);

            //Inserting sharing of image into database
            $stmt = $this->db->prepare("INSERT INTO shared_image VALUES (?,?);");
            $stmt->bind_param("ii", $uid, $iid);
            $stmt->execute();

			return mysqli_affected_rows($this->db) == 1;
        }
		return false;
    }

    // This function returns a list of users whom the given image can be shared with
    // returns a list of users if successful, otherwise false
    function getUsersToShareWith($iid){
        if(self::isUserLoggedIn() && self::isOwner($iid)){
            $users = array();

			// Query database for users to share with, which is everyone but the owner 
			// and those whom the image is already shared with.
            $uid = self::getUid();
            
            $stmt = $this->db->prepare("SELECT id,username FROM user WHERE id <> ? AND id NOT IN (SELECT user_id FROM shared_image WHERE image_id = ?);");
            $stmt->bind_param("ii", $uid, $iid);
            $stmt->execute();
            $result = $stmt->get_result();

			if (mysqli_num_rows($result) > 0) {
				while ($row = mysqli_fetch_assoc($result)) {
					$users[] = new user($row['id'], $row['username']);
				}
		    } else {
		        return "No users to share this with.";
		    }			

            return $users;
        }
        return false;
    }

    // This function returns a list of users whom the given image is shared with.
    // returns a list of users if successful, otherwise false
    function sharedWith($iid){
        if(self::isUserLoggedIn()) {
            $users = array();
            
            $stmt = $this->db->prepare("SELECT id,username FROM user INNER JOIN shared_image ON id = user_id WHERE image_id = (?);");
            $stmt->bind_param("i", $iid);
            $stmt->execute();
			$result = $stmt->get_result();

			if (mysqli_num_rows($result) > 0) {
				while ($row = mysqli_fetch_assoc($result)) {
					$users[] = new user($row['id'], $row['username']);
				}
		    }

            return $users;
        }
        return false;
    }

	// This function saves the image to a file with the corresponding image id as the name.
	// TODO: Find out how to handle the file permissions.
	function save_image($img, $iid){
		$data = base64_decode(preg_replace('#^data:image/\w+;base64,#i', '', $img));
		$file = self::$image_dir.$iid;
		file_put_contents($file, $data);
		chmod($file, 0777); // This works for now, but probably isn't necessary... right?
	}

	// This function loads the image file with the corresponding image id.
	// TODO: Find out how to handle the file permissions.
	function loadImage($iid){
		$file = self::$image_dir.$iid;
		$type = pathinfo($file, PATHINFO_EXTENSION);	
		$data = file_get_contents($file);
		$img = 'data:image/' . $type . ';base64,' . base64_encode($data);		
		return $img;
	}

    // This function returns a list of all images shared with the loggedin user
    // returns a list of images if successful, otherwise false
    function getImages(){
        if(self::isUserLoggedIn()){
            $images = array();
			
			// The images to display should either be those owned by the user
			// or those ahred with the user and should not be duplicated.
            $uid = self::getUid();
            $stmt = $this->db->prepare("SELECT DISTINCT image.id,owner_id,username,createdDate FROM image INNER JOIN user on user.id = owner_id LEFT JOIN shared_image ON image_id = image.id WHERE user_id = (?) OR owner_id = (?) ORDER BY createdDate DESC");
            $stmt->bind_param("ii", $uid, $uid);
            $stmt->execute();
            $result = $stmt->get_result();

			if (mysqli_num_rows($result) > 0) {
				while ($row = mysqli_fetch_assoc($result)) {
					$iid = $row['id'];
					$img = self::loadImage($iid);
					$images[] = new Image($iid, $row['owner_id'], $row['username'], $img, $row['createdDate']);
				}
		    }

            return $images;
        }
        return false;
    }

    // This function returns the given image iff the loggedin user have access to it
    // returns the image if successful, otherwise false
    function getImage($iid)
    {
        if(self::isUserLoggedIn())
        {
            $uid = self::getUid();
            $stmt = $this->db->prepare("SELECT image.id,owner_id,username,createdDate FROM image INNER JOIN user ON user.id = owner_id LEFT JOIN shared_image ON image_id = image.id WHERE (user_id = ? OR owner_id = ?) AND image.id = ?;");
            $stmt->bind_param("iii", $uid, $uid, $iid);
            $stmt->execute();
			$result = $stmt->get_result();
			
			if (mysqli_num_rows($result) > 0) {
				$row = mysqli_fetch_assoc($result);
			
				$img = self::loadImage($iid);
				return new Image($iid, $row['owner_id'], $row['username'], $img, $row['createdDate']);
			}
			return null;
        }

        return false;
    }

    // This function will post given comment to given image iff the loggedin user has access to post
    // returns true if successful, otherwise false
    function comment($iid, $comment)
    {
        if(self::isUserLoggedIn() && self::verifyShare(self::getUid(), $iid))
        {
            $uid = self::getUid();
            $stmt = $this->db->prepare("INSERT INTO post(text, user_id, image_id) VALUES (?,?,?);");
            $cmt = $this->db->real_escape_string($comment);
            $stmt->bind_param("sii", $cmt, $uid, $iid);
            $stmt->execute();
			return mysqli_affected_rows($this->db) == 1;
        }
        return false;
    }

    // This function gets all comments for the given image
    // returns a list of comments if successful, otherwise false
    function getComments($iid)
    {
        if(self::isUserLoggedIn() && self::verifyShare(self::getUid(), $iid))
      	{			
            $comments = array();

            $stmt = $this->db->prepare("SELECT post.id,username,text,createdDate FROM post INNER JOIN user ON user_id = user.id WHERE image_id = (?) ORDER BY createdDate ASC;");
            $stmt->bind_param("i", $iid);
            $stmt->execute();
			$result = $stmt->get_result();

			if (mysqli_num_rows($result) > 0) {
				while ($row = mysqli_fetch_assoc($result)) {
					// Only include verified comments
					$text = $row['text'];
					if ((self::verifyInput($text))) {
						$comments[] = new Comment($row['id'], $row['username'], $text, $row['createdDate']);
					}
				}
		    }

            return $comments;
        }
        return false;
    }

    // This function checks if the loggedin user is owner of the given image
    // returns true if the loggedin user is owner, otherwise false
    function isOwner($iid){
        $uid = self::getUid();
        $stmt = $this->db->prepare("SELECT id FROM image WHERE owner_id = (?) AND id = (?);");
        $stmt->bind_param("ii", $uid, $iid);
        $stmt->execute();
		$result = $stmt->get_result();
		return mysqli_num_rows($result) > 0;
    }

	// This function will verify whether the given user input is bad. 
	// This is to prevent malicious users from sending bad input, e.g. NULL, 
	// which would cause the MySQL service to crash.
	// Returns true if no bad input is detected, otherwise false.
	function verifyInput($input) {
		$valid = !(eval('"'.$input.'"===NULL;') || eval('"'.$input.'"==="\0";'));
		return $valid;
	}

    // This function checks if the loggedin user is either owner or has access to the given image
    // returns true if the loggedin user has access, otherwise false
    function verifyShare($uid, $iid) {
        $stmt = $this->db->prepare("SELECT id FROM image LEFT JOIN shared_image ON image_id = id WHERE (user_id = ? OR owner_id = ?) AND id = ?;");
        $stmt->bind_param("iii", $uid, $uid, $iid);
        $stmt->execute();
		$result = $stmt->get_result();
		return mysqli_num_rows($result) > 0;
    }
}

class User{
    private $_id;
    private $_name;

    public function __construct($id, $name){
        $this -> _id = $id;
        $this -> _name = $name;
    }

    public function getName(){ return $this -> _name; }
    public function getId(){ return $this -> _id; }
}

// This class is kind of obsolete, but still used.
// Might be used in the future to, like, maybe store images in a database?
class Image{

    private $_id;
    private $_ownerId;
    private $_image;
    private $_username;
    private $_datetime;

    public function __construct($id, $ownerId, $username, $image, $datetime){
        $this -> _id = $id;
        $this -> _ownerId = $ownerId;
        $this -> _image = $image;
        $this -> _username = $username;
        $this -> _datetime = new DateTime($datetime);
    }

    public function getId() { return $this -> _id; }
    public function getOwnerId() { return $this -> _ownerId; }
    public function getUser() { return $this -> _username; }
    public function getImage() { return $this -> _image; }
    public function getAge() {
        $date = $this -> _datetime;
        $currentDate = new DateTime();
        $dateDiff = $date -> diff($currentDate);
        $years = $dateDiff -> y;
        $months = $dateDiff -> m;
        $days = $dateDiff -> d;
        $hours = $dateDiff -> h;
        $minutes = $dateDiff -> i;
        $seconds = $dateDiff -> s;


        if($years > 1) return $years .' years';
        if($years > 0) return $years .' year';
        if($months > 1) return $months .' months';
        if($months > 0) return $months .' month';
        if($days > 1) return $days .' days';
        if($days > 0) return $days .' day';
        if($hours > 1) return $hours .' hours';
        if($hours > 0) return $hours .' hour';
        if($minutes > 1) return $minutes .' minutes';
        if($minutes > 0) return $minutes .' minute';
        if($seconds > 1) return $seconds .' seconds';
        if($seconds >= 0) return $seconds .' second';
        return "Error!";
    }
}

class Comment{
    private $_id;
    private $_userName;
    private $_text;
    private $_datetime;

    public function __construct($id, $userName, $text, $datetime){
        $this -> _id = $id;
        $this -> _userName = $userName;
        $this -> _text = $text;
        $this -> _datetime = new DateTime($datetime);
    }

    public function getId() { return $this -> _id; }
    public function getUser() { return $this -> _userName; }
    public function getText() { return $this -> _text; }
    public function getAge() {
        $date = $this -> _datetime;
        $currentDate = new DateTime();
        $dateDiff = $date -> diff($currentDate);
        $years = $dateDiff -> y;
        $months = $dateDiff -> m;
        $days = $dateDiff -> d;
        $hours = $dateDiff -> h;
        $minutes = $dateDiff -> i;
        $seconds = $dateDiff -> s;


        if($years > 1) return $years .' years';
        if($years > 0) return $years .' year';
        if($months > 1) return $months .' months';
        if($months > 0) return $months .' month';
        if($days > 1) return $days .' days';
        if($days > 0) return $days .' day';
        if($hours > 1) return $hours .' hours';
        if($hours > 0) return $hours .' hour';
        if($minutes > 1) return $minutes .' minutes';
        if($minutes > 0) return $minutes .' minute';
        if($seconds > 1) return $seconds .' seconds';
        if($seconds >= 0) return $seconds .' second';
        return "Error!";
    }
}
?>
