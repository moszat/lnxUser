# lnxUser PHP class

Linux user and group management in PHP.

Basically this library a php interface of useradd, groupadd, usermod, groupmod, userdel, groupdel, mkpasswd linux commands. You can manage easily the linux users and groups with this library from a php apllication.

# Requirements

Of course this library can work just **linux environment**.  
The running user of php environment must has **root privileges** for manage the users and groups.  
Must enable the **shell_exec** function.  
This library should use the **mkpasswd** linux command, you have to install it if necessary.  
Tested on Ubuntu with **PHP 7.0 - 8.1** versions.  

# Features

* Create a linux user or a group.
* Get all information about a linux user or a group.
* Set all attributes of a linux user or a group.
* Delete a linux user or a group.
* Examine if exists a linux user or a group.
* Authenticate a linux user.
* Generate password hash.

# Documentation

browse [Documentation](https://doc.onlinesoft.org/index.php?title=LnxUser_PHP_Class_Reference)

# Usage

`sudo php example.php`
