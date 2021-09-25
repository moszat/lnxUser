<?php
/**
 * lnxUser PHP Class
 * 
 * @author moszat <moszat@onlinesoft.org>
 * @copyright 2021 moszat
 * @license GPL 3
 * @version 1.2
 * 
 * See the https://doc.onlinesoft.org/index.php?title=LnxUser_PHP_Class_Reference for the documentation. 
 */

define( 'LNX_PH_DES',			'DES' );
//define( 'LNX_PH_EDES',			'EDES' );
define( 'LNX_PH_MD5',			'MD5' );
define( 'LNX_PH_BLOWFISH_A',	'BCRYPT_A' );
define( 'LNX_PH_BLOWFISH_B',	'BCRYPT_B' );
define( 'LNX_PH_BLOWFISH_X',	'BCRYPT_X' );
define( 'LNX_PH_BLOWFISH_Y',	'BCRYPT_Y' );
define( 'LNX_PH_SHA256',		'SHA256' );
define( 'LNX_PH_SHA512',		'SHA512' );

class lnxUser 
{

	/**
	 * Private system vars
	 *
	 * @var array $user
	 * @var array $usersByID
	 * @var array $groups
	 * @var array $groupsByID
	 * @var string $defaultPasswordHash 
	 * @var string $defaultPasswordSalt 
	 * @var string $defaultPasswordRound 
	 */
	private	$users;
	private	$usersByID;
	private	$groups;
	private	$groupsByID;
	private $defaultPasswordHash = '';
	private $defaultPasswordSalt = '';
	private $defaultPasswordRound = '';

	/**
	 * Load (or reload) information of user and group from linux system files to system vars
	 */
	function __construct()
	{
		global $lnxDefaultPasswordHash;

		$passwd			    = preg_split( "/((\r?\n)|(\r\n?))/", file_get_contents('/etc/passwd' ) );
		$shadow			    = preg_split( "/((\r?\n)|(\r\n?))/", file_get_contents('/etc/shadow' ) );
		$group			    = preg_split( "/((\r?\n)|(\r\n?))/", file_get_contents('/etc/group' ) );
		$this->users		= [];
		$this->groups		= [];
		$this->usersByID	= [];
		$this->groupsByID	= [];

		foreach( $passwd as $line )
			if( !empty( trim( $line ) ) ) {
				$line   = explode( ':',$line );
				$this->users[$line[0]]  = [
					'name'      => $line[0],
					'uid'	    => (int)$line[2],
					'gid'	    => (int)$line[3],
					'comment'	=> $line[4],
					'home'	    => $line[5],
					'shell'	    => $line[6],
					'groups'	=> []
					];
				$this->usersByID[(int)$line[2]] = $line[0];
			}

		foreach( $shadow as $line )
			if( !empty( trim( $line ) ) ) {
				$line   = explode( ':',$line );
				$this->users[$line[0]]  += [
					'lastchanged'	=> (int)$line[2],
					'min'		    => (int)$line[3],
					'password'		=> $line[1],
					'warn'		    => (int)$line[5],
					'max'		    => (int)$line[4],
					'expire'		=> (int)$line[7],
					'inactive'		=> (int)$line[6],
				];
			}

		foreach( $group as $line )
			if( !empty( trim( $line ) ) ) {
				$line   = explode( ':',$line );
				$this->groups[$line[0]] = [
					'name'	    => $line[0],
					'gid'	    => (int)$line[2],
					'members'	=> explode(',',$line[3]),
				];
				$this->groupsByID[(int)$line[2]]=   $line[0];
			}

		foreach($this->groups as $group)
			foreach( $group['members'] as $key=>$member )
			if( empty( $member ) )
				unset( $this->groups[$group['name']]['members'][$key] );
			else
				foreach( explode( ',', $member) as $user )
					if( !empty( trim( $user ) ) )
						$this->users[$user]['groups'][]=$group['name'];

		foreach( $this->users as $user ){
			if( array_search( $user['name'], $this->groups[$this->groupsByID[$user['gid']]]['members'], true ) === false )
				$this->groups[$this->groupsByID[$user['gid']]]['members'][] = $user['name'];
			if( array_search( $this->groupsByID[$user['gid']], $user['groups'], true ) === false )
				$this->users[$user['name']]['groups'][] = $this->groupsByID[$user['gid']];
			}

		if ( empty( $this->defaultPasswordHash ) )
			$this->setDefaultPasswordHash( $lnxDefaultPasswordHash );

	}
	
	/**
	 * Examine that the linux user is exists.
	 *
	 * @param	int|string $user
	 * @return	boolean
	 */
	public function existsUser( $user ):bool
	{

		if ( is_numeric( $user ) )
			return isset($this->usersByID[(int)$user]);
		if ( is_string( $user ) )
			return isset($this->users[$user]);
		return false;

	}

	/**
	 * Examine that the linux group is exists.
	 *
	 * @param	int|string $group
	 * @return	boolean
	 */
	public function existsGroup( $group ):bool
	{

		if ( is_numeric( $group ) )
			return isset($this->groupsByID[(int)$group]);
		if ( is_string( $group ) )
			return isset($this->groups[$group]);
		return false;

	}

	/**
	 * Returns informations about the linux user.
	 *
	 * @param 	int|string $user
	 * @return 	array
	 */
	public function getUser( $user ):array
	{

		if(!$this->existsUser($user))
			return false;

		if ( is_numeric( $user ) )
			$user	= $this->usersByID[(int)$user];

		return $this->users[$user];

	}

	/**
	 * Returns informations about the linux group.
	 *
	 * @param int|string $group
	 * @return array
	 */
	public function getGroup( $group ):array
	{

		if(!$this->existsGroup($group))
			return false;

		if ( is_numeric( $group ) )
			$group	= $this->groupsByID[(int)$group];

		return $this->groups[$group];

	}

	/**
	 * Create a linux user with $user parameters
	 *
	 * @param array $user
	 * @return boolean
	 */
	public function addUser( array $user ):bool
	{

		//conditions
		if ( !isset($user['name'] ) )												{ trigger_error( "'name' array index is not set!", E_USER_WARNING );									return false; }
		if ( !isset($user['password'] ) )											{ trigger_error( "'password' array index is not set!", E_USER_WARNING );								return false; }
		if ( !is_string( $user['name'] ) )											{ trigger_error( "'name' array element must be an instance of string!", E_USER_WARNING );				return false; }
		if ( !is_string( $user['password'] ) )										{ trigger_error( "'password' array element must be an instance of string!", E_USER_WARNING );			return false; }
		if ( $this->existsUser( $user['name'] ) )									{ trigger_error( "'".$user['name']."' user is exist!", E_USER_WARNING );								return false; }
		if ( isset( $user['uid'] ) ) {
			if ( !is_numeric( $user['uid'] ) )										{ trigger_error( " User ID must be an instance of numeric!", E_USER_WARNING );							return false; }
			if ( !isset( $user['nonunique'] ) && $this->existsUser( $user['uid'] ) ){ trigger_error( $user['uid']." User ID is exists", E_USER_WARNING );									return false; }
		}
		if ( isset( $user['gid'] ) ) {
			if ( !$this->existsGroup( $user['gid'] ) )								{ trigger_error( $user['gid']." Group ID is not exists", E_USER_WARNING );								return false; }
			if ( is_numeric( $user['gid'] ) )										$user['gid'] = (int)$user['gid'];
		}
		if ( isset( $user['groups'] ) ) {
			if ( is_string( $user['groups'] ) )										$user['groups']	= explode( ',', $user['groups'] );
			if ( !is_array( $user['groups'] ) )										{ trigger_error( "'groups' array element must be an instance of array or string!", E_USER_WARNING );	return false; }
			foreach( $user['groups'] as $group )
				if ( !$this->existsGroup( $group ) )								{ trigger_error( $group." Group is not exists", E_USER_WARNING );										return false; }
		}
		if ( !isset($user['hash']) ) 												$user['hash'] = $this->getDefaultPasswordHash();
		if ( !isset($user['salt']) )												$user['salt'] = '';
		if ( !isset($user['round']) )												$user['round'] = '';
		if ( !$this->chkHash( $user['hash'] ) )										return false;
		if ( !$this->chkSalt( $user['hash'], $user['salt'] ) )						return false;
		if ( !$this->chkRound( $user['hash'], $user['round'] ) )					return false;

		//defaults
		$user['name']		= substr($user['name'],0,32);
		$user['password']	= $this->getPassHash( $user['password'], $user['hash'],  $user['salt'], $user['round'] );
		if ( empty( $user['password'] ) )											return false;

		//set command
		$command = 'if ERR=$( useradd';
		if ( isset( $user['uid'] ) )
			$command.=' -u '.(int)$user['uid'];
		if ( isset( $user['gid'] ) )
			$command.=' -g '.$user['gid'];
		elseif	( isset( $user['nogroup'] )	)
			$command.=' -N';
		if ( isset( $user['groups'] ) )
			$command.=' -G '.implode( ',', $user['groups'] );
		if ( isset( $user['home'] ) )
			$command.=' -d '.(string)$user['home'];
		if ( isset( $user['createhome'] )	&& $user['createhome'] === false )
			$command.=' -M';
		else
			$command.=' -m';
		if ( isset( $user['comment'] ) )
			$command.=' -c "'.addslashes( $user['comment'] ).'"';
		if ( isset( $user['shell'] ) )
			$command.=' -s '.(string)$user['shell'];
		if ( isset( $user['expire'] ) )
			$command.=' -e '.(int)$user['expire'];
		if ( isset( $user['inactive'] ) )
			$command.=' -f '.(int)$user['inactive'];
		if ( isset( $user['system'] ) )
			$command.=' -r';
		if ( isset( $user['nonunique'] ) )
			$command.=' -o';
		$command.=' -p "'.str_replace( '$', '\$', $user['password'] ).'" '.$user['name'].' 2>&1); then echo "OK"; else echo $ERR; fi';

		// run command
		$out = preg_replace('/((\r?\n)|(\r\n?))/', '', shell_exec( $command ));
		if ( $out !== 'OK' )														{ trigger_error( $out, E_USER_WARNING );	return false; }

		$this->__construct();
		return true;

	}

	/**
	 * Create a linux group with $group parameters.
	 *
	 * @param array $group
	 * @return boolean
	 */
	public function addGroup ( array $group ):bool
	{

		//conditions
		if ( !isset( $group['name'] ) )												{ trigger_error( "'name' array index is not set!", E_USER_WARNING );						return false; }
		if ( !is_string( $group['name'] ) )											{ trigger_error( "'name' array element must be an instance of string!", E_USER_WARNING );	return false; }
		if ( $this->existsGroup( $group['name'] ) )									{ trigger_error( "'".$group['name']."' group is exist!", E_USER_WARNING );					return false; }
		if ( isset( $group['gid'] ) ) {
			if ( !is_numeric( $group['gid'] ) )										{ trigger_error( " Group ID must be an instance of numeric!", E_USER_WARNING );				return false; }
			if ( 
				!isset( $group['nonunique'] ) 
				&& $this->existsGroup( $group['gid'] ) 
				)																	{ trigger_error( $group['gid']." Group ID is exists", E_USER_WARNING );						return false; }
		}

		//defaults
		$group['name']		= substr( $group['name'], 0, 32 );

		//set command
		$command = 'if ERR=$( groupadd';
		if ( isset( $group['gid'] ) )
			$command.=' -g '.(int)$group['gid'];
		if ( isset( $group['system'] ) )
			$command.=' -r';
		if ( isset( $group['nonunique'] ) )
			$command.=' -o';
		$command.=' '.$group['name'].' 2>&1); then echo "OK"; else echo $ERR; fi';

		// run command
		$out = preg_replace('/((\r?\n)|(\r\n?))/', '', shell_exec( $command ));
		if ( $out !== 'OK' )														{ trigger_error( $out, E_USER_WARNING );	return false; }

		$this->__construct();
		return true;

	}

	/**
	 * Modify a linux user with $user parameters
	 *
	 * @param array $user
	 * @return boolean
	 */
	public function modifyUser( array $user ):bool
	{

		//conditions
		if ( !isset($user['name'] ) )												{ trigger_error( "'name' array index is not set!", E_USER_WARNING );									return false; }
		if ( !is_string( $user['name'] ) )											{ trigger_error( "'name' array element must be an instance of string!", E_USER_WARNING );				return false; }
		if ( isset( $user['password'] )	) {
			if ( !is_string( $user['password'] ) )									{ trigger_error( "'password' array element must be an instance of string!", E_USER_WARNING );			return false; }
			if ( !isset($user['hash']) ) 											$user['hash'] = $this->getDefaultPasswordHash();
			if ( !isset($user['salt']) )											$user['salt'] = '';
			if ( !isset($user['round']) )											$user['round'] = '';
			if ( !$this->chkHash( $user['hash'] ) )									return false;
			if ( !$this->chkSalt( $user['hash'], $user['salt'] ) )					return false;
			if ( !$this->chkRound( $user['hash'], $user['round'] ) )				return false;
			$user['password']	= $this->getPassHash( $user['password'], $user['hash'],  $user['salt'], $user['round'] );
			
		} 
		if ( !$this->existsUser( $user['name'] ) )									{ trigger_error( "'".$user['name']."' user is not exist!", E_USER_WARNING );							return false; }
		if ( isset( $user['uid'] ) ) {
			if ( !is_numeric( $user['uid'] ) )										{ trigger_error( " User ID must be an instance of numeric!", E_USER_WARNING );							return false; }
			if ( !isset( $user['nonunique'] ) && $this->existsUser( $user['uid'] ) ){ trigger_error( $user['uid']." User ID is exists", E_USER_WARNING );									return false; }
		}
		if ( isset( $user['gid'] ) ) {
			if ( !$this->existsGroup( $user['gid'] ) )								{ trigger_error( $user['gid']." Group ID is not exists", E_USER_WARNING );								return false; }
			if ( is_numeric( $user['gid'] ) )										$user['gid'] = (int)$user['gid'];
		}
		if ( isset( $user['groups'] ) ) {
			if ( is_string( $user['groups'] ) )										$user['groups']	= explode( ',', $user['groups'] );
			if ( !is_array( $user['groups'] ) )										{ trigger_error( "'groups' array element must be an instance of array or string!", E_USER_WARNING );	return false; }
			foreach( $user['groups'] as $group )
				if ( !$this->existsGroup( $group ) )								{ trigger_error( $group." Group is not exists", E_USER_WARNING );										return false; }
		}
		if ( isset( $user['rename'] ) ) {
			if ( !is_string( $user['rename'] ) )									{ trigger_error( "'rename' array element must be an instance of string!", E_USER_WARNING );				return false; }
			if ( $this->existsUser( $user['rename'] ) )								{ trigger_error( "'".$user['rename']."' user is exist!", E_USER_WARNING );								return false; }
		}
		if ( isset( $user['lock'] ) && ! is_bool( $user['lock'] ) )					{ trigger_error( "'lock' array element must be an instance of boolean!", E_USER_WARNING );				return false; }
		if ( isset( $user['lock'] ) && isset( $user['password'] ) )					{ trigger_error( "Password and lock options are exclusive!", E_USER_WARNING );							return false; }
		if ( count( $user) == 1)													{ trigger_error( "There is no option!", E_USER_WARNING );												return false; }


		//set command
		$command = 'if ERR=$( usermod';
		if ( isset( $user['password'] ) )
			$command.=' -p "'.str_replace( '$', '\$', $user['password'] ).'"';
		if ( isset( $user['uid'] ) )
			$command.=' -u '.(int)$user['uid'];
		if ( isset( $user['gid'] ) )
			$command.=' -g '.$user['gid'];
		if ( isset( $user['groups'] ) )
			$command.=' -G '.implode( ',', $user['groups'] );
		if ( isset( $user['home'] ) ) {
			if ( isset( $user['movehome'] )	&& $user['movehome'] === true )
				$command.=' -m';
			$command.=' -d '.(string)$user['home'];
		}
		if ( isset( $user['comment'] ) )
			$command.=' -c "'.addslashes( $user['comment'] ).'"';
		if ( isset( $user['shell'] ) )
			$command.=' -s '.(string)$user['shell'];
		if ( isset( $user['expire'] ) )
			$command.=' -e '.(int)$user['expire'];
		if ( isset( $user['inactive'] ) )
			$command.=' -f '.(int)$user['inactive'];
		if ( isset( $user['nonunique'] ) )
			$command.=' -o';
		if ( isset( $user['append'] ) )
			$command.=' -a';
		if ( isset( $user['rename'] ) )
			$command.=' -l '.substr($user['rename'],0,32);
		if ( isset( $user['lock'] ) && $user['lock'] === true )
			$command.=' -L';
		if ( isset( $user['lock'] ) && $user['lock'] === false )
			$command.=' -U';

		$command.=' '.$user['name'].' 2>&1); then echo "OK"; else echo $ERR; fi';

		// run command
		$out = preg_replace('/((\r?\n)|(\r\n?))/', '', shell_exec( $command ));
		if ( $out !== 'OK' )														{ trigger_error( $out, E_USER_WARNING );	return false; }

		$this->__construct();
		return true;

	}

	/**
	 * Modify a linux group with $group parameters.
	 *
	 * @param array $group
	 * @return boolean
	 */
	public function modifyGroup ( array $group ):bool
	{

		//conditions
		if ( !isset( $group['name'] ) )												{ trigger_error( "'name' array index is not set!", E_USER_WARNING );						return false; }
		if ( !is_string( $group['name'] ) )											{ trigger_error( "'name' array element must be an instance of string!", E_USER_WARNING );	return false; }
		if ( !$this->existsGroup( $group['name'] ) )								{ trigger_error( "'".$group['name']."' group is not exist!", E_USER_WARNING );				return false; }
		if ( isset( $user['gid'] ) ) {
			if ( !is_numeric( $user['gid'] ) )										{ trigger_error( " Group ID must be an instance of numeric!", E_USER_WARNING );				return false; }
			if ( 
				!isset( $user['nonunique'] ) 
				&& $this->existsGroup( $user['gid'] ) 
				)																	{ trigger_error( $user['gid']." Group ID is exists", E_USER_WARNING );						return false; }
		}
		if ( isset( $group['rename'] ) ) {
			if ( !is_string( $group['rename'] ) )									{ trigger_error( "'rename' array element must be an instance of string!", E_USER_WARNING );	return false; }
			if ( $this->existsGroup( $group['rename'] ) )							{ trigger_error( "'".$group['rename']."' group is exist!", E_USER_WARNING );				return false; }
		}
		if ( count( $group ) == 1)													{ trigger_error( "There is no option!", E_USER_WARNING );									return false; }

		//set command
		$command = 'if ERR=$( groupmod';
		if ( isset( $group['gid'] ) )
			$command.=' -g '.(int)$group['gid'];
		if ( isset( $group['rename'] ) )
			$command.=' -n '.substr($group['rename'],0,32);
		if ( isset( $group['nonunique'] ) )
			$command.=' -o';
		$command.=' '.$group['name'].' 2>&1); then echo "OK"; else echo $ERR; fi';

		// run command
		$out = preg_replace('/((\r?\n)|(\r\n?))/', '', shell_exec( $command ));
		if ( $out !== 'OK' )														{ trigger_error( $out, E_USER_WARNING );	return false; }

		$this->__construct();
		return true;

	}

	/**
	 * Delete a linux user.
	 *
	 * @param int|string|array $user
	 * @return boolean
	 */
	public function deleteUser( $user ):bool
	{

		//conditions
		if ( !is_array( $user ) )													$user 			= [ 'name' => $user ];
		if ( !isset( $user['name'] ) )												{ trigger_error( "'name' array index is not set!", E_USER_WARNING );						return false; }
		if ( !$this->existsUser( $user['name'] ) )									{ trigger_error( "'".$user['name']."' user is not exist!", E_USER_WARNING );				return false; }
		if ( is_numeric( $user['name'] ) )											$user['name']	= $this->usersByID[ (int)$user['name'] ];

		//set command
		$command = 'if ERR=$( userdel';
		if ( isset( $user['remove'] ) && $user['remove'] === true ) 
			$command.=' -r';
		if ( isset( $user['force'] ) && $user['force'] === true )
			$command.=' -f';
		$command.=' '.$user['name'].' 2>&1); then echo "OK"; else echo $ERR; fi';

		// run command
		$out = preg_replace('/((\r?\n)|(\r\n?))/', '', shell_exec( $command ));
		if ( $out !== 'OK' )														{ trigger_error( $out, E_USER_WARNING );	return false; }

		$this->__construct();
		return true;

	}

	/**
	 * Delete a linux group.
	 *
	 * @param int|string|array $group
	 * @return boolean
	 */
	public function deleteGroup( $group ):bool
	{

		//conditions
		if ( !is_array( $group ) )													$group 			= [ 'name' => $group ];
		if ( !isset( $group['name'] ) )												{ trigger_error( "'name' array index is not set!", E_USER_WARNING );						return false; }
		if ( !$this->existsGroup( $group['name'] ) )								{ trigger_error( "'".$group['name']."' group is not exist!", E_USER_WARNING );				return false; }
		if ( is_numeric( $group['name'] ) )											$group['name']	= $this->groupsByID[ (int)$group['name'] ];

		//set command
		$command = 'if ERR=$( groupdel';
		if ( isset( $group['force'] )	&& $group['force'] === true )
			$command.=' -f';
		$command.=' '.$group['name'].' 2>&1); then echo "OK"; else echo $ERR; fi';

		// run command
		$out = preg_replace('/((\r?\n)|(\r\n?))/', '', shell_exec( $command ));
		if ( $out !== 'OK' )														{ trigger_error( $out, E_USER_WARNING );	return false; }

		$this->__construct();
		return true;

	}

	/**
	 * Authenticate a linux user.
	 * MD5, SHA-256, SHA-512 password hash methods are implemented.
	 *
	 * @param string $user
	 * @param string $password
	 * @return boolean
	 */
	public function authUser( $user, string $password ):bool
	{

		if ( !$this->existsUser( $user ) )											return false;
		if ( is_numeric( $user ) )													$user			= $this->usersByID[ (int)$user ];
		if ( empty( $this->users[$user]['password'] )
			|| substr( $this->users[$user]['password'], 0, 1 ) == '!'
		)																			return false;
		$salt	= '';
		$round	= '';

		switch ( substr($this->users[$user]['password'], 0 ,1 ) ) {
/*			case '_':
				$hash	= LNX_PH_EDES;
				$salt	= substr($this->users[$user]['password'], 5 ,4 );
				$round	= substr($this->users[$user]['password'], 1 ,4 );
			break;*/
			case '$':
				$pass		= explode( '$', $this->users[$user]['password'] );
				foreach( $pass as $key => $value )
					if ( empty( $value ) )
						unset( $pass[ $key ] );
				switch ( $pass[1] ) {
					case '1':
						$hash = LNX_PH_MD5;
						$salt		= $pass[2];
					break;
					case '2a':
						$hash = LNX_PH_BLOWFISH_A;
						$round	= $pass[2];
						$salt	= substr($pass[3],0,22);
					break;
					case '2b':
						$hash = LNX_PH_BLOWFISH_B;
						$round	= $pass[2];
						$salt	= substr($pass[3],0,22);
					break;
					case '2x':
						$hash = LNX_PH_BLOWFISH_X;
						$round	= $pass[2];
						$salt	= substr($pass[3],0,22);
					break;
					case '2y':
						$hash = LNX_PH_BLOWFISH_Y;
						$round	= $pass[2];
						$salt	= substr($pass[3],0,22);
					break;
					case '5':
						$hash = LNX_PH_SHA256;
						if ( count( $pass ) == 4 ) {
							$round	= $pass[2];
							$salt	= $pass[3];
						} else {
							$salt	= $pass[2];
						}
					break;
					case '6':
						$hash = LNX_PH_SHA512;
						if ( count( $pass ) == 4 ) {
							$round	= $pass[2];
							$salt	= $pass[3];
						} else {
							$salt	= $pass[2];
						}
					break;
					default:
						trigger_error ('Unknown hash method type: '.$this->users[$user]['password'], E_USER_WARNING);
						return false;
				}
			break;
			default:
				$hash	= LNX_PH_DES;
				$salt	= substr($this->users[$user]['password'], 0 ,2 );
		}

		$auth = $this->users[$user]['password'] == $this->getPassHash( $password, $hash, $salt, $round );
		openlog('lnxUser', LOG_PID, LOG_AUTHPRIV );
		if ( $auth ) 
			syslog(LOG_NOTICE, "Authentication success for user '$user'");
		else
			syslog(LOG_ERR, "Authentication failure for user '$user'");
		closelog();

		return $auth;

	}

	/**
	 * Determines if a linux user is member of a group.
	 *
	 * @param string $user
	 * @param string $group
	 * @return boolean
	 */
	public function isMember ( $user, $group ):bool
	{

		if ( !$this->existsGroup( $group ) )										{ trigger_error( "'$group' group is not exist!", E_USER_WARNING );							return false; }
		if ( !$this->existsUser( $user ) )											{ trigger_error( "'$user' user is not exist!", E_USER_WARNING );							return false; }
		if ( is_numeric( $user ) )													$user	= $this->usersByID[ (int)$user ];
		if ( is_numeric( $group ) )													$group	= $this->groupsByID[ (int)$group ];
		
		$user	= (string)$user;
		$group	= (string)$group;
		
		return is_numeric( array_search( $user, $this->groups[$group]['members'], true ) );

	}

	/**
	 * Creates a password hash.
	 *
	 * @param string $password
	 * @param string $hash
	 * @param string $salt
	 * @param string|int $round
	 * @return string
	 */
	public function getPassHash( string $password, string $hash = '' , string $salt = '', $round = ''):string
	{

		$password	= addslashes($password);
		$charsok	= '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
		if ( empty( $hash ) )
			$hash = $this->defaultPasswordHash;
		if ( ! $this->chkHash( $hash ) ) 
			return '';
		
		if ( $salt !== '' ) {
			// Verify salt
			if ( ! $this->chkSalt( $hash, $salt ) ) 
				return '';
		} else {
			// Generate salt
			switch ( $hash ) {
				case LNX_PH_DES:
					$salt = substr(str_shuffle( $charsok ), 0, 2);
				break;
//				case LNX_PH_EDES:
				case LNX_PH_MD5:
					$salt = substr(str_shuffle( $charsok ), 0, 4);
				break;
				case LNX_PH_BLOWFISH_A:
				case LNX_PH_BLOWFISH_B:
				case LNX_PH_BLOWFISH_X:
				case LNX_PH_BLOWFISH_Y:
					$salt = substr(str_shuffle( $charsok ), 0, 22);
				break;
				case LNX_PH_SHA256:
				case LNX_PH_SHA512:
					$salt = substr(str_shuffle( $charsok ), 0, 16);
				break;
			}
		}
		
		if ( $round !== '' ) {
			// Verify round
			if ( ! $this->chkRound( $hash, $round ) ) 
				return '';
		} else {
			// Generate round
			switch ( $hash ) {
/*				case LNX_PH_EDES:
					$round	= str_pad( substr(str_shuffle( $charsok ), 0, rand( 1, 3) ), 4, '.', STR_PAD_RIGHT);
				break;*/
				case LNX_PH_BLOWFISH_A:
				case LNX_PH_BLOWFISH_B:
				case LNX_PH_BLOWFISH_X:
				case LNX_PH_BLOWFISH_Y:
					$round	= str_pad( (string)rand(4, 10), 2, '0', STR_PAD_LEFT);
				break;
			}
		}
		
		// make hash
		switch ( $hash ) {
			case LNX_PH_DES:
				$retVal = crypt($password, $salt);
			break;
/*			case LNX_PH_EDES:
				$retVal = crypt($password, '_'.$round.$salt);
			break;*/
			case LNX_PH_MD5:
				$retVal = crypt($password, '$1$'.$salt);
			break;
			case LNX_PH_BLOWFISH_A:
				$retVal = crypt($password, '$2a$'.$round.'$'.$salt);
			break;
			case LNX_PH_BLOWFISH_B:
				$retVal = crypt($password, '$2b$'.$round.'$'.$salt);
			break;
			case LNX_PH_BLOWFISH_X:
				$retVal = crypt($password, '$2x$'.$round.'$'.$salt);
			break;
			case LNX_PH_BLOWFISH_Y:
				$retVal = crypt($password, '$2y$'.$round.'$'.$salt);
			break;
			case LNX_PH_SHA256:
				$cryptInput	= '$5$';
				if ( ! empty( $round ) )
					$cryptInput	.= $round.'$';
				$cryptInput	.= $salt;
				$retVal = crypt($password, $cryptInput);
			break;
			case LNX_PH_SHA512:
				$cryptInput	= '$6$';
				if ( ! empty( $round ) )
					$cryptInput	.= $round.'$';
				$cryptInput	.= $salt;
				$retVal = crypt($password, $cryptInput);
			break;
		}

		if ( $retVal == '*0') {
			trigger_error ("Crypt error! salt: $salt hash: $hash", E_USER_WARNING);
			return '';
		}
		
		return $retVal;

	}

	/**
	 * Set default password hash
	 *
	 * @param string $hash
	 * @return boolean
	 */
	public function setDefaultPasswordHash( string $hash, string $salt = '', $round = ''  ):bool
	{
		if ( ! $this->chkHash( $hash ) ) 
			return false;
		if ( ! $this->chkSalt( $hash, $salt ) ) 
			return false;
		if ( ! $this->chkRound( $hash, $round ) ) 
			return false;
		$this->defaultPasswordHash = $hash;
		$this->defaultPasswordSalt = $salt;
		$this->defaultPasswordRound = $round;
		return true;
	}

	/**
	 * Get default password hash
	 *
	 * @return string
	 */
	public function getDefaultPasswordHash():string
	{
		return $this->defaultPasswordHash;
	}

	/**
	 * Get default password salt
	 *
	 * @return string
	 */
	public function getDefaultPasswordSalt():string
	{
		return $this->defaultPasswordSalt;
	}

	/**
	 * Get default password round
	 *
	 * @return string
	 */
	public function getDefaultPasswordRound():string
	{
		return $this->defaultPasswordRound;
	}

	/**
	 * Verify hash type
	 *
	 * @param string $hash
	 * @return bool
	 */
	public function chkHash( string $hash ):bool
	{
		if ( ! in_array( $hash, [ LNX_PH_DES, LNX_PH_MD5, LNX_PH_BLOWFISH_A, LNX_PH_BLOWFISH_B, LNX_PH_BLOWFISH_X, LNX_PH_BLOWFISH_Y, LNX_PH_SHA256, LNX_PH_SHA512 ] ) ) {
			trigger_error ("Unknown hash method type $hash!", E_USER_WARNING);
			return false;
		} else 
			return true;
	}

	/**
	 * Verify salt
	 *
	 * @param string $hash
	 * @param string $salt
	 * @return bool
	 */
	public function chkSalt( string $hash, string $salt ):bool
	{
		if ( ! $this->chkHash( $hash ) ) 
			return false;
		if ( $salt === '')
			return true;
		$charsok	= '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ./';
		for ( $i=0; $i < strlen( $salt ); $i++ ) 
			if ( strpos( $charsok, substr( $salt, $i, 1) ) === false  ) {
				trigger_error ("Salt is not alphanumeric!", E_USER_WARNING);
				return false;
			}
		switch ( $hash ) {
			case LNX_PH_DES:
				if ( strlen( $salt ) != 2) {
					trigger_error ("Salt length must be 2 characters!", E_USER_WARNING);
					return false;
				}
			break;
/*			case LNX_PH_EDES:
				if ( strlen( $salt ) != 4 ) {
					trigger_error ("Salt length must be 4 characters!", E_USER_WARNING);
					return false;
				}
			break;*/
			case LNX_PH_MD5:
				if ( strlen( $salt ) < 4 || strlen( $salt ) > 8 ) {
					trigger_error ("Salt length must be between 4 and 8 characters!", E_USER_WARNING);
					return false;
				}
			break;
			case LNX_PH_BLOWFISH_A:
			case LNX_PH_BLOWFISH_B:
			case LNX_PH_BLOWFISH_X:
			case LNX_PH_BLOWFISH_Y:
				if ( strlen( $salt )!= 22 ) {
					trigger_error ("Salt length must be 22 characters!", E_USER_WARNING);
					return false;
				}
			break;
			case LNX_PH_SHA256:
			case LNX_PH_SHA512:
				if ( strlen( $salt ) < 8 || strlen( $salt ) > 16 ) {
					trigger_error ("Salt length must be between 8 and 16 characters!", E_USER_WARNING);
					return false;
				}
			break;
		}
		return true;
	}

	/**
	 * Verify salt
	 *
	 * @param string $hash
	 * @param string|int $round
	 * @return bool
	 */
	public function chkRound( string $hash, &$round ):bool
	{
		if ( ! $this->chkHash( $hash ) ) 
			return false;
		if ( $round === '')
			return true;
		if ( ! is_string( $round ) && ! is_int( $round ) ) {
			trigger_error ("Round type is not string or integer!", E_USER_WARNING);
			return false;
		}
		$charsok	= '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';

		switch ( $hash ) {
/*			case LNX_PH_EDES:
				if ( strlen( (string)$round ) > 4 ) {
					trigger_error ("Round can be up to 4 characters!", E_USER_WARNING);
					return false;
				}
				for ( $i=0; $i < strlen( (string)$round ); $i++ ) 
					if ( strpos( $charsok, substr( (string)$round, $i, 1) ) === false  ) {
						trigger_error ("Round is not alphanumeric!", E_USER_WARNING);
						return false;
					}
				$round	= str_pad( (string)$round, 4, '.', STR_PAD_LEFT);
				return true;
			break;*/
			case LNX_PH_BLOWFISH_A:
			case LNX_PH_BLOWFISH_B:
			case LNX_PH_BLOWFISH_X:
			case LNX_PH_BLOWFISH_Y:
				if ((int)$round < 4 || (int)$round > 31 ) {
					trigger_error ("Round value be between 4 and 31 !", E_USER_WARNING);
					return false;
				}
				$round	= str_pad( (string)$round, 2, '0', STR_PAD_LEFT);
				return true;
			break;
			case LNX_PH_SHA256:
			case LNX_PH_SHA512:
				if ((int)$round < 1000 || (int)$round > 999999999 ) {
					trigger_error ("Round value be between 1000 and 999999999 !", E_USER_WARNING);
					return false;
				}
				$round	= 'rounds='.(string)$round;
				return true;
			break;
		}
		return false;
	}

}

/**
 * Handle of static calls
 *
 * @return callback
 */
function lnxStaticHandle()
{

	global $lnxStaticObject;
	if( !isset( $lnxStaticObject ) )
		$lnxStaticObject = new lnxUser;
	$arguments	= func_get_args();
	$func		= $arguments[0];
	unset( $arguments[0] );

	return call_user_func_array( [ $lnxStaticObject, $func ], $arguments );

}

/**
 * Static functions
 */
function lnxExistsUser( $user )																	{ return lnxStaticHandle( 'existsUser',				$user ); }
function lnxExistsGroup( $group )																{ return lnxStaticHandle( 'existsGroup',			$group ); }
function lnxGetUser( $user )																	{ return lnxStaticHandle( 'getUser',				$user ); }
function lnxgetGroup( $group )																	{ return lnxStaticHandle( 'getGroup',				$group ); }
function lnxAddUser( array $user )																{ return lnxStaticHandle( 'addUser',				$user ); }
function lnxAddGroup( array $group )															{ return lnxStaticHandle( 'addGroup',				$group ); }
function lnxModifyUser( array $user )															{ return lnxStaticHandle( 'modifyUser',				$user ); }
function lnxModifyGroup( array $group )															{ return lnxStaticHandle( 'modifyGroup',			$group ); }
function lnxDeleteUser( $user )																	{ return lnxStaticHandle( 'deleteUser',				$user ); }
function lnxDeleteGroup( $group )																{ return lnxStaticHandle( 'deleteGroup',			$group ); }
function lnxAuthUser( $user, string $pass )														{ return lnxStaticHandle( 'authUser',				$user, $pass ); }
function lnxIsMember ( $user, $group )															{ return lnxStaticHandle( 'isMember',				$user, $group ); }
function lnxGetPassHash( string $password, string $hash ='', string $salt = '', $round = '' )	{ return lnxStaticHandle( 'getPassHash',			$password, $hash, $salt, $round ); }
function lnxSetDefaultPasswordHash( string $hash, string $salt = '', $round = ''  )				{ return lnxStaticHandle( 'setDefaultPasswordHash',	$hash, $salt, $round ); }
function lnxGetDefaultPasswordHash()															{ return lnxStaticHandle( 'getDefaultPasswordHash'	); }
function lnxChkHash( string $hash )																{ return lnxStaticHandle( 'chkHash',				$hash ); }
function lnxChkSalt( string $hash, string $salt )												{ return lnxStaticHandle( 'chkSalt',				$hash, $salt ); }
function lnxChkRound( string $hash, &$round )													{ return lnxStaticHandle( 'chkRound',				$hash, $round ); }

/**
 * Verify requirements
 */
function lnxCheckRequirements () {
	global $lnxDefaultPasswordHash;

	// Is linux system files readable?

	if	(
		!is_readable( '/etc/passwd' )
	||	!is_readable( '/etc/shadow' )
	||	!is_readable( '/etc/group' )
		)
		throw new ErrorException ('System files are not readable! ( /etc/passwd , /etc/shadow, /etc/group ) Are you root?');

	// Is shell_exec function enabled?

	if ( !function_exists( 'shell_exec' ) )
		throw new ErrorException ('shell_exec function is not enabled!');

	// Get system default password hash method

	$loginConfigFile = '/etc/login.defs';
	if	( is_readable( $loginConfigFile ) ) {
		$t_array = preg_grep( "/^ENCRYPT_METHOD .*$/", file( $loginConfigFile, FILE_IGNORE_NEW_LINES) );
		if ( count ($t_array) != 1 )
			trigger_error ("$loginConfigFile parse error!", E_USER_WARNING);
		else {
			$t_array = preg_split('/\s+/', $t_array[ array_key_first( $t_array ) ] );
			$hash =  $t_array[1];
			if ( ! lnxUser::chkHash( $hash ) ) 
				trigger_error ("System ENCRYPT_METHOD $hash is unknown in $loginConfigFile", E_USER_WARNING);
			else
				$lnxDefaultPasswordHash = $hash;
		}
	} else 
		trigger_error ("$loginConfigFile is not readable!", E_USER_WARNING);

}

$lnxDefaultPasswordHash = LNX_PH_SHA512;
lnxCheckRequirements ();