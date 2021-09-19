<?php
/**
 * lnxUser PHP Class usage examples
 * 
 * @author moszat <moszat@onlinesoft.org>
 * @copyright 2021 moszat
 * @license GPL 3
 * @version 1.00
 * 
 * See the https://doc.onlinesoft.org/index.php?title=LnxUser_PHP_Class_Reference for the documentation. 
 */

require('lnxUser.class.php');

$user	= 'testUser';
$group	= 'testGroup';

# Add linux user

if ( ! lnxAddUser( [
	
	'name'			=> $user,		// Mantandory! Name of linux user.
	'password'		=> 'HelloNSA',	// Mantandory! Password of linux user.
	//'uid'			=> 1100,		// Optional. User ID of linux user. The ID must not exist!
	//'gid'			=> 1100,		// Optional. Primary group of the linux user. The group must exist! If this parameter is not present the Group name will be the User name and the Group ID will be the User ID or the first free ID.
	'groups'		=> [ 'users' ],	// Optional. Group membership of the linux user. It must be a simple indexed array what contains the groups in what the user will be member. The groups must exist.
	//'nogroup'		=> true,		// Optional. If true the Primary group will not be created. If 'gid' is present this parameter will be ineffective.
	'comment'		=> 'test user',	// Optional. Comment (display name) of linux user.
	//'home'		=> '/home/test',// Optional. Absolute path of Home directory of linux user.
	//'createhome'	=> true,		// Optional. If false the Home directory will not be created.
	//'shell'		=> '/bin/bash',	// Optional. Absolute path of shell for linux user.
	//'inactive'	=> 90,			// Optional. The number of days after password expires that account is disabled.
	//'expire'		=> 1640995199,	// Optional. Date when account will be disabled. Format: timestamp.
	//'system'		=> true,		// Optional. If true create a system account. User ID will be under 1000. If 'uid' is present this parameter will be ineffective.
	//'nonunique'	=> true	,		// Optional. If true allow to create users with duplicate (non-unique) User ID.
	
	] ) )
	
	print( "Something went wrong during Add user!" . PHP_EOL );

else
	
	print( "'$user' user is created." . PHP_EOL );


# Add linux group

if ( ! lnxAddGroup( [
	
	'name'			=> $group,		// Mantandory! Name of linux group.
	//'gid'			=> 1011,		// Optional. Group ID of linux group. The ID must not exist!
	//'system'		=> true,		// Optional. If true create a system group. Group ID will be under 1000. If 'gid' is present this parameter will be ineffective.
	//'nonunique'	=> true,		// Optional. If true allow to create groups with duplicate (non-unique) Group ID

	] ) )
	
	print( "Something went wrong during Add group!" . PHP_EOL );

else
	
	print( "'$group' group is created." . PHP_EOL );

# Examine if user exists

if ( lnxExistsUser( $user ) )
	
	print( "'$user' user exists!" . PHP_EOL );

else
	
	print( "'$user' user does not exists!" . PHP_EOL );

# Examine if group exists

if ( lnxExistsGroup( $group ) )
	
	print( "'$group' group exists!" . PHP_EOL );

else
	
	print( "'$group' group does not exists!" . PHP_EOL );

# Modify linux user

if ( ! lnxModifyUser ( [

	'name'			=> $user,				// Mantandory! Name of linux user.
	//'rename'		=> 'renamedTestUser',	// Optional. Change of the linux user name.
	'password'		=> 'HelloAgainNSA',		// Optional. Change of the linux user password.
	//'uid'			=> 1200,				// Optional. Change of User ID of linux user. The ID must not exist!
	//'gid'			=> 1200,				// Optional. Change of primary group of linux user. The group must exist!
	'groups'		=> [ $group ],			// Optional. Change of group membership. It must be a simple indexed array what contains the groups in what the user will be member. The groups must exist.
	'append'		=> true,				// Optional. If true, append the user to the supplemental groups mentioned by the 'groups' option, without removing the user from other groups. If 'groups' is not present this parameter will be ineffective.
	'comment'		=> 'Renamed Test User',	// Optional. Change of comment (display name) of linux user.
	//'home'		=> '/home/newtest',		// Optional. Change of absolute path of Home directory of linux user.
	//'movehome'	=> true,				// Optional. If true, move contents of the Home directory to the new location. If 'home' is not present this parameter will be ineffective.
	//'shell'		=> '/bin/sh',			// Optional. Change of absolute path of shell for linux user.
	//'inactive'	=> 90,					// Optional. Change of the number of days after password expires that account is disabled.
	//'expire'		=> 1640995199,			// Optional. Change of date when account will be disabled. Format: timestamp.
	//'nonunique'	=> true,				// Optional. If true, allow to create users with duplicate (non-unique) User ID.
	//'lock'		=> false,				// Optional. If true lock, if false unlock the user account.
	
	] ) )
	
	print( "Something went wrong during Modify user!" . PHP_EOL );

else
	
	print( "'$user' user is modified." . PHP_EOL );

# Modify linux group

if ( ! lnxModifyGroup ( [

	'name'			=> $group,				// Mantandory! Name of linux group.
	//'rename'		=> 'RenamedTestGroup',	// Optional. New name of the linux group.
	'gid'			=> 1200,				// Optional. Group ID of linux group. The ID must not exist!
	//'nonunique'	=> true,				// Optional. If true allow to create groups with duplicate (non-unique) Group ID
	
	] ) )
	
	print( "Something went wrong during Modify group!" . PHP_EOL );

else
	
	print( "'$group' group is modified." . PHP_EOL );

# Query information about the linux user

print( "Information of '$user' user:" . PHP_EOL );

if ( lnxExistsUser( $user ) ) 

	foreach ( lnxGetUser ( $user ) as $key => $value ) {

		print( $key . ' : ' );

		if ( is_array( $value ) ) 

			print( implode ( ',', $value ) );

		else

			print( $value );

		print( PHP_EOL );

	}

# Query information about the linux group

print( "Information of '$group' group:" . PHP_EOL );

if ( lnxExistsGroup( $group ) )

	foreach ( lnxGetGroup ( $group ) as $key => $value ) {

		print( $key . ' : ' );

		if ( is_array( $value ) ) 

			print( implode ( ',', $value ) );

		else

			print( $value );

		print( PHP_EOL );

	}

# Authenticate linux user

if ( lnxAuthUser( $user, 'HelloAgainNSA' ) )

	print( "'$user' user authentication is success!" . PHP_EOL );

else
	
	print( "'$user' user authentication is failed!" . PHP_EOL );

# Examine if user is a member of the group

if ( lnxIsMember( $user, $group ) )

	print( "'$user' user is in the '$group' group." . PHP_EOL );

else
	
	print( "'$user' user is not in the '$group' group." . PHP_EOL );

# Delete linux user

if ( ! lnxDeleteUser ( $user ) )
	
	print( "Something went wrong during Delete user!" . PHP_EOL );

else
	
	print( "'$user' user is deleted." . PHP_EOL );

# Delete linux group

if ( ! lnxDeleteGroup ( $group ) )
	
	print( "Something went wrong during Delete group!" . PHP_EOL );

else
	
	print( "'$group' group is deleted." . PHP_EOL );
