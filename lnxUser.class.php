<?php
/**
 * lnxUser PHP Class
 * 
 * @author moszat <moszat@onlinesoft.org>
 * @copyright 2021 moszat
 * @license GPL 3
 * @version 1.00
 * 
 * See the lnxUser.doc.html for the documentation. 
 */

define( 'LNX_PH_MD5',		'md5' );
define( 'LNX_PH_SHA256',	'sha-256' );
define( 'LNX_PH_SHA512',	'sha-512' );

class lnxUser 
{

	/**
	 * Private system vars
	 *
	 * @var array $user
	 * @var array $usersByID
	 * @var array $groups
	 * @var array $groupsByID
	 */
	private	$users;
	private	$usersByID;
	private	$groups;
	private	$groupsByID;

	/**
	 * Load (or reload) information of user and group from linux system files to system vars
	 */
	function __construct()
	{

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
		//defaults
		$user['name']		= substr($user['name'],0,32);
		$user['password']	= $this->getPassHash( $user['password'] );

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
		if ( isset( $user['password'] )	&& !is_string( $user['password'] ) )		{ trigger_error( "'password' array element must be an instance of string!", E_USER_WARNING );			return false; }
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
			$command.=' -p "'.str_replace( '$', '\$', $this->getPassHash( $user['password'] ) ).'"';
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
	public function authUser( $user, $password ):bool
	{

		if ( !$this->existsUser( $user ) )											return false;
		if ( is_numeric( $user ) )													$user			= $this->usersByID[ (int)$user ];
		if ( empty( $this->users[$user]['password'] )
			|| substr( $this->users[$user]['password'], 0, 1 ) == '!'
		)																			return false;

		$password	= (string)$password;
		$pass		= explode( '$', $this->users[$user]['password'] );
		$salt		= $pass[2];
		switch ( $pass[1] ) {
			case '1':
				$hash = LNX_PH_MD5;
			break;
			case '5':
				$hash = LNX_PH_SHA256;
			break;
			case '6':
				$hash = LNX_PH_SHA512;
			break;
			default:
				trigger_error ('Unknown hash method type: '.$this->users[$user]['password'], E_USER_WARNING);
				return false;
		}

		return $this->users[$user]['password'] == trim(`mkpasswd -m $hash $password $salt`);

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
	 * @return string
	 */
	public function getPassHash( $password, $salt = '', $hash = LNX_PH_SHA512 ):string
	{

		$password	= (string)addslashes($password);
		$salt		= (string)$salt;
		$hash		= strtolower( $hash );

		if ( ! in_array( $hash, [ LNX_PH_MD5, LNX_PH_SHA256, LNX_PH_SHA512 ] ) ) {
			trigger_error ("Unknown hash method type: $hash!", E_USER_WARNING);
			return '';
		}
		if ( $salt !== '' ) {
			if ( !ctype_alnum( $salt ) ) {
				trigger_error ("Salt is not alphanumeric!", E_USER_WARNING);
				return '';
			}
			if ( strlen( $salt ) < 8 || strlen( $salt ) > 16 ) {
				trigger_error ("Salt length must be between 8 and 16 characters!", E_USER_WARNING);
				return '';
			}
		}

		return preg_replace( "/\r|\n/", "",shell_exec("mkpasswd -m $hash \"$password\" $salt"));

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
function lnxExistsUser( $user ):bool											{ return lnxStaticHandle( 'existsUser',		$user ); }
function lnxExistsGroup( $group ):bool											{ return lnxStaticHandle( 'existsGroup',	$group ); }
function lnxGetUser( $user ):array												{ return lnxStaticHandle( 'getUser',		$user ); }
function lnxgetGroup( $group ):array											{ return lnxStaticHandle( 'getGroup',		$group ); }
function lnxAddUser( array $user ):bool											{ return lnxStaticHandle( 'addUser',		$user ); }
function lnxAddGroup( array $group ):bool										{ return lnxStaticHandle( 'addGroup',		$group ); }
function lnxModifyUser( array $user ):bool										{ return lnxStaticHandle( 'modifyUser',		$user ); }
function lnxModifyGroup( array $group ):bool									{ return lnxStaticHandle( 'modifyGroup',	$group ); }
function lnxDeleteUser( $user ):bool											{ return lnxStaticHandle( 'deleteUser',		$user ); }
function lnxDeleteGroup( $group ):bool											{ return lnxStaticHandle( 'deleteGroup',	$group ); }
function lnxAuthUser( $user, $pass ):bool										{ return lnxStaticHandle( 'authUser',		$user, $pass ); }
function lnxIsMember ( $user, $group ):bool										{ return lnxStaticHandle( 'isMember',		$user, $group ); }
function lnxGetPassHash( $password, $salt = '', $hash = LNX_PH_SHA512 ):string	{ return lnxStaticHandle( 'getPassHash',	$password, $salt, $hash ); }

/**
 * Verify requirements
 */
if ( !empty( trim( `if ! test -f /bin/mkpasswd; then echo 'error'; fi` ) ) )
	throw new ErrorException('mkpassword command not found!');

if	(
	!is_readable( '/etc/passwd' )
||	!is_readable( '/etc/shadow' )
||	!is_readable( '/etc/group' )
	)
	throw new ErrorException ('System files are not readable! ( /etc/passwd , /etc/shadow, /etc/group ) Are you root?');

if ( !function_exists( 'shell_exec' ) )
	throw new ErrorException ('shell_exec function is not enabled!');
