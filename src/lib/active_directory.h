/**
 * Copyright (c) by: Mike Dawson mike _at_ no spam gp2x.org
 *
 * This file may be used subject to the terms and conditions of the
 * GNU Library General Public License Version 2, or any later version
 * at your option, as published by the Free Software Foundation.
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Library General Public License for more details.
 *
**/

#ifndef ACTIVE_DIRECTORY_H
#define ACTIVE_DIRECTORY_H 1

/* Configuration options:
|  For configuration these functions look first for the file 
| ~/.adtool.cfg, or failing that
| /(install prefix)/etc/adtool.cfg
|  An example would look like:
uri ldaps://dc2.example.com
binddn cn=administrator,ou=admin,dc=example,dc=com
bindpw passw0rd
searchbase ou=users,dc=example,dc=com
|  Any function may return: 
|	AD_COULDNT_OPEN_CONFIG_FILE or AD_MISSING_CONFIG_PARAMETER.
| if there is a problem reading the config file, or
|	AD_SERVER_CONNECT_FAILURE if a connection can't be made.
*/
char *system_config_file;
char *uri;
char *binddn;
char *bindpw;
char *search_base;

/* ad_get_error() returns a pointer to a string containing an
| explanation of the last error that occured.
|  If no error has previously occured the string the contents are 
| undefined.
|  Subsequent active directory library calls may over-write this
| string.
*/
char *ad_get_error();

/* ad_get_error_num() returns the integer code for the last error
| that occured.
|  If no function calls have previously failed the result is undefined.
|  See the end of this header file for the list of error codes.
*/
int ad_get_error_num();

/* ad_create_user() creates a new, locked user account
| with the given user name and distinguished name
|  Example usage: 
| ad_create_user("nobody", "cn=nobody,ou=users,dc=example,dc=com");
|  Returns AD_SUCCESS on success, or
| AD_LDAP_OPERATION_FAILURE.
|  Attributes set:
|	objectClass=user
|	sAMAccountName=username
|	userPrincipalName=username@<domain> (derived from dn)
|	userAccountControl=66050
| (ACCOUNTDISABLE|NORMAL_ACCOUNT|DONT_EXPIRE_PASSWORD)
| see http://msdn.microsoft.com/library/default.asp?url=/library/en-us/netdir/adsi/ads_user_flag_enum.asp for flags.
|  Attributes set automatically by the directory:
|	objectclass=top,person,organizationalPerson
|	accountExpires,instanceType,objectCategory,objectGUID,
|	objectSid,
|	primaryGroupID=513
|	name=username
|	sAMAccountType=805306368
|	uSNChanged,uSNCreated,whenChanged,whenCreated
*/
int ad_create_user(char *username, char *dn);

/* create computer object */
int ad_create_computer(char *name, char *dn);

/* ad_lock_user() disables a user account
|  Returns AD_SUCCESS, AD_OBJECT_NOT_FOUND or AD_LDAP_OPERATIONS_FAILURE.
*/
int ad_lock_user(char *dn);

/* ad_unlock_user() unlocks a disabled user account
|  Returns AD_SUCCESS, AD_OBJECT_NOT_FOUND or AD_LDAP_OPERATIONS_FAILURE.
*/
int ad_unlock_user(char *dn);

/* ad_object_delete() deletes the given dn
|  Returns AD_SUCCESS or AD_LDAP_OPERATION_FAILURE.
*/
int ad_object_delete(char *dn);

/* ad_setpass() sets the user's password to the password string given
|  This requires an ssl connection to work 
| (use a uri of ldaps:// rather than ldap:// in the configuration file)
|  Returns AD_SUCCESS or AD_LDAP_OPERATION_FAILURE.
*/
int ad_setpass(char *dn, char *password);

/* ad_search() is a more generalised search function
|  Returns a NULL terminated array of dns which match the given 
| attribute and value or NULL if no results are found.  
|  Returns -1 on error.
|  Sets error code to AD_SUCCESS, AD_OBJECT_NOT_FOUND 
| or AD_LDAP_OPERATION_FAILURE.
|  Searching is done from the searchbase specified in the configuration
| file.
*/
char **ad_search(char *attribute, char *value);

/* ad_mod_add() adds a value to the given attribute.
| Example ad_mod_add("cn=nobody,ou=users,dc=example,dc=com",
|		"mail", "nobody@nowhere");
|  This function works only on multi-valued attributes.
|  Returns AD_SUCCESS on success.
*/
int ad_mod_add(char *dn, char *attribute, char *value);

/* ad_mod_add_binary()
|  Works the same as ad_mod_add() except for binary data.
|  Returns AD_SUCCESS or AD_LDAP_OPERATION_FAILURE.
*/
int ad_mod_add_binary(char *dn, char *attribute, char *data, int data_length);

/* ad_mod_replace() overwrites the given attribute with a new value.
| Example ad_mod_replace("cn=nobody,ou=users,dc=example,dc=com",
|		"description", "some person");
|  On multi-valued attributes this replaces all values.
|  Returns AD_SUCCESS or AD_LDAP_OPERATION_FAILURE.
*/
int ad_mod_replace(char *dn, char *attribute, char *value);

/* ad_mod_replace_binary()
|  Works the same as ad_mod_replace() except for binary data.
|  Returns AD_SUCCESS or AD_LDAP_OPERATION_FAILURE.
*/
int ad_mod_replace_binary(char *dn, char *attribute, char *data, int data_length);

/* ad_mod_delete() removes attribute data from an object.
|  If user nobody has 'othertelephone' numbers
| '123' and '456' then ad_mod_delete(dn, "othertelephone", "123"
| will delete just the number '123', whereas:
| ad_mod_delete(dn, "othertelephone", NULL)
| will delete both numbers.
|  Returns AD_SUCCESS or AD_LDAP_OPERATION_FAILURE.
*/
int ad_mod_delete(char *dn, char *attribute, char *value);

/* ad_get_attribute() returns a pointer to a NULL terminated
| array of strings containing values for the given attribute.
|  Returns NULL on failure or if nothing is found.
|  Sets error code to AD_SUCCESS, AD_OBJECT_NOT_FOUND, 
| AD_ATTRIBUTE_ENTRY_NOT_FOUND or AD_LDAP_OPERATION_FAILURE
| even if there are no values for the given attribute.
*/
char **ad_get_attribute(char *dn, char *attribute);

/* ad_rename_user() changes the given user's name
| Modifies cn, sAMAccountName and userPrincipalName
|to the new username.  Assumes that the first part of the dn
|is composed of cn=username.
|  Returns AD_SUCCESS or AD_LDAP_OPERATION_FAILURE;
*/
int ad_rename_user(char *dn, char *new_username);

/* ad_move_user() moves a user into a different container/organizational
| unit.
|  Changes dn and fixes userPrincipalName in case of domain change.
|  Returns AD_SUCCESS, AD_INVALID_DN or AD_LDAP_OPERATION_FAILURE.
*/
int ad_move_user(char *current_dn, char *new_container);

/* ad_group_create() creates a new user group (of type global security)
|  Example ad_group_create("administrators",
|	"cn=administrators,ou=admin,dc=example,dc=com");
|  Sets objectclass=group,
| sAMAccountName=group name
|  The directory automatically sets:
| objectclass=top
| groupType,instanceType,objectCategory,objectGUID,objectSid,
| name,sAMAccountType,uSNChanged,uSNCreated,whenChanged,whenCreated
|  Returns AD_SUCCESS or AD_LDAP_OPERATION_FAILURE.
*/
int ad_group_create(char *group_name, char *dn);

/* ad_group_add_user()
| adds a user to a group
| Returns AD_SUCCESS or AD_LDAP_OPERATION_FAILURE.
*/
int ad_group_add_user(char *group_dn, char *user_dn);

/* ad_group_remove_user()
| removes a user from a group
| Returns AD_SUCCESS or AD_LDAP_OPERATION_FAILURE.
*/
int ad_group_remove_user(char *group_dn, char *user_dn);

/* ad_group_subtree_remove_user()
|  Removes the user from all groups underneath the given container
|  Returns AD_SUCCESS or AD_LDAP_OPERATION_FAILURE.
*/
int ad_group_subtree_remove_user(char *container_dn, char *user_dn);

/* ad_ou_create()
|  Create an organizational unit
|  Sets objectclass=organizationalUnit
|  Returns AD_SUCCESS or AD_LDAP_OPERATION_FAILURE.
*/
int ad_ou_create(char *ou_name, char *dn);

/* ad_list()
|  Return NULL terminated array of entries
*/
char **ad_list(char *dn);

/* Error codes */
#define AD_SUCCESS 1
#define AD_COULDNT_OPEN_CONFIG_FILE 2
#define AD_MISSING_CONFIG_PARAMETER 3
#define AD_SERVER_CONNECT_FAILURE 4
#define AD_LDAP_OPERATION_FAILURE 5
#define AD_OBJECT_NOT_FOUND 6
#define AD_ATTRIBUTE_ENTRY_NOT_FOUND 7
#define AD_INVALID_DN 8

#endif /* ACTIVE_DIRECTORY_H */
