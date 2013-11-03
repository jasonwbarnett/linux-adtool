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

#define ADTOOL_VERSION "1.3.3"

#include <active_directory.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>

void usage() {
	printf(
		"usage:\n"
		"adtool [connection options] operation [arguments...]\n"
		"\n"
		"options:\n"
		"-h		print this help text\n"
		"-v		output version information\n"
		"-H uri         server uri, eg. ldaps://ad1.example.com\n"
		"-D binddn      dn to bind to server with\n"
		"-w password    password to bind to server with\n"
		"-b basedn      base for operations that involve searches\n"
		"\n"
		"These options may alternatively be read from %s or ~/.adtool.cfg.  Command line options override those in the config file.\n"
		"\n"
		"operations:\n"
		"usercreate         <username> <container>          create a new user\n"
		"userdelete         <username>                      delete a user\n"
		"userlock           <username>                      disable a user account\n"
		"userunlock         <username>                      enable a user account\n"
		"setpass            <user> [password]               set user's password\n"
		"usermove           <user> <new container>          move user to another container\n"
		"userrename         <old username> <new username>   rename user\n"
		"\n"
		"computercreate     <computer name> <container>     create a computer account\n"
		"\n"
		"groupcreate        <group name> <container>        create a new group\n"
		"groupdelete        <group name>                    delete a group\n"
		"groupadduser       <group> <user>                  add a user to a group\n"
		"groupremoveuser    <group> <user>                  remove a user from a group\n"
		"groupsubtreeremove <container> <user>              remove a user from all groups below a given ou\n"
		"\n"
		"oucreate           <organizational unit name> <container>\n"
		"                                                   create a new organizational unit\n"
		"oudelete           <organizational unit name>      delete an organizational unit\n"
		"\n"
		"attributeget       <object> <attribute>            display attribute values\n"
		"attributeadd       <object> <attribute> <value>    add an attribute\n"
		"attributeaddbinary <object> <attribute> <filename> add an attribute from a file\n"
		"attributereplace   <object> <attribute> <value>    replace an attribute\n"
		"attributedelete    <object> <attribute> [value]    delete an attribute or attribute instance\n"
		"\n"
		"search             <attribute> <value>             simple ldap search\n"
		"\n",
		system_config_file);
}

void useradd(char **argv) {
	char *username;
	char *container;
        int result, dn_length;
        char *dn;

	username=argv[0];
	container=argv[1];

        dn_length=strlen(username)+strlen(container)+5;
        dn=malloc(dn_length);
        snprintf(dn, dn_length, "cn=%s,%s", username, container);
        result=ad_create_user(username, dn);
        if(result!=AD_SUCCESS) {
                fprintf(stderr, "error: %s\nCan't create %s\n",
                        ad_get_error(), dn);
		exit(1);
        }
}

void userdelete(char **argv){
	char *user;
        int result;
        char **dn;

	user=argv[0];

        dn=ad_search("name", user);
        if(ad_get_error_num()!=AD_SUCCESS) {
                fprintf(stderr, "error: %s\n", ad_get_error());
                exit(1);
        }

        result=ad_object_delete(*dn);
        if(result!=AD_SUCCESS) {
                fprintf(stderr, "error, user %s could not be deleted:\n%s\n", *dn, ad_get_error());
		exit(1);
        }
}

void userlock(char **argv) {
	char *username;
        char **dn;
        int result;

	username=argv[0];

        dn=ad_search("name", username);
        if(ad_get_error_num()!=AD_SUCCESS) {
                fprintf(stderr, "error: %s\n", ad_get_error());
                exit(1);
        }

        result=ad_lock_user(*dn);

        if(result!=AD_SUCCESS) {
                fprintf(stderr, "error: %s\n", ad_get_error());
		exit(1);
	}
}

void userunlock(char **argv) {
	char *username;
        char **dn;
        int result;

	username=argv[0];

        dn=ad_search("name", username);
        if(ad_get_error_num()!=AD_SUCCESS) {
                fprintf(stderr, "error: %s\n", ad_get_error());
                exit(1);
        }

        result=ad_unlock_user(*dn);

        if(result!=AD_SUCCESS) {
		fprintf(stderr, "error: %s\n", ad_get_error());
		exit(1);
	}
}

void setpass(char **argv) {
	char *username;
	char *password;
	char *password2;
	char **dn;
	int result;

	username=argv[0];

	if(argv[1]==NULL) {
		password=getpass("Password:");
		password2=strdup(password);
		password=getpass("Re-enter password:");
		if(strcmp(password, password2)) {
			fprintf(stderr, "Error: passwords don't match\n");
			exit(1);
		}
	} else {
		password=strdup(argv[1]);
		memset(argv[1], 0, strlen(argv[1]));
	}

	dn=ad_search("name", username);
	if(ad_get_error_num()!=AD_SUCCESS) {
		fprintf(stderr, "error: %s\n", ad_get_error());
		exit(1);
	}
	result=ad_setpass(*dn, password);
	free(password);
	if(result!=AD_SUCCESS) {
		fprintf(stderr, "error: %s\n", ad_get_error());
		fprintf(stderr, "Ensure openldap is built with ssl support, and that you are using a secure connection to your active directory server (ldaps:// rather than plain ldap://).\n");
		exit(1);
	}
}

void usermove(char **argv) {
	char *username;
	char *new_container;
        char **dn;
        int result;

	username=argv[0];
	new_container=argv[1];

        dn=ad_search("name", username);
        if(ad_get_error_num()!=AD_SUCCESS) {
                fprintf(stderr, "error: %s\n", ad_get_error());
                exit(1);
        }

        result=ad_move_user(*dn, new_container);
        free(dn);

        if(result!=AD_SUCCESS) {
                fprintf(stderr, "error: %s\n", ad_get_error());
                exit(1);
	}
}

void userrename(char **argv) {
	char *old_username;
	char *new_username;
        char **dn;
        int result;

	old_username=argv[0];
	new_username=argv[1];

        dn=ad_search("name", old_username);
        if(ad_get_error_num()!=AD_SUCCESS) {
                fprintf(stderr, "error: %s\n", ad_get_error());
                exit(1);
        }

        result=ad_rename_user(*dn, new_username);
        free(dn);
        if(result!=AD_SUCCESS) {
                fprintf(stderr, "error: %s\n", ad_get_error());
                exit(1);
	}
}

void computercreate(char **argv) {
	char *name;
	char *container;
        int result, dn_length;
        char *dn;

	name=argv[0];
	container=argv[1];

        dn_length=strlen(name)+strlen(container)+5;
        dn=malloc(dn_length);
        snprintf(dn, dn_length, "cn=%s,%s", name, container);
        result=ad_create_computer(name, dn);
        if(result!=AD_SUCCESS) {
                fprintf(stderr, "error: %s\nCan't create %s\n",
                        ad_get_error(), dn);
		exit(1);
        }
}

void groupadd(char **argv) {
	char *group;
	char *container;
        int result, dn_length;
        char *dn;

	group=argv[0];
	container=argv[1];

        dn_length=strlen(group)+strlen(container)+5;
        dn=malloc(dn_length);
        snprintf(dn, dn_length, "cn=%s,%s", group, container);
        result=ad_group_create(group, dn);
        if(result!=AD_SUCCESS) {
                fprintf(stderr, "error: %s\n", ad_get_error());
		exit(1);
        }
}

void groupdelete(char **argv){
	char *group;
        int result;
        char **dn;

	group=argv[0];

        dn=ad_search("name", group);
        if(ad_get_error_num()!=AD_SUCCESS) {
                fprintf(stderr, "error: %s\n", ad_get_error());
                exit(1);
        }

        result=ad_object_delete(*dn);
        if(result!=AD_SUCCESS) {
                fprintf(stderr, "error, group %s could not be deleted:\n%s\n", *dn, ad_get_error());
		exit(1);
        }
}

void groupadduser(char **argv) {
	char *group;
	char *user;
        char **group_dn, **user_dn;

	group=argv[0];
	user=argv[1];

        group_dn=ad_search("cn", group);
        if(ad_get_error_num()!=AD_SUCCESS) {
                fprintf(stderr, "error: %s\n", ad_get_error());
                exit(1);
        }

        user_dn=ad_search("name", user);
        if(ad_get_error_num()!=AD_SUCCESS) {
                fprintf(stderr, "error: %s\n", ad_get_error());
                exit(1);
        }

        if(ad_group_add_user(*group_dn, *user_dn)!=AD_SUCCESS) {
                fprintf(stderr, "error adding user %s to group %s:\n%s",
                        *user_dn, *group_dn, ad_get_error());
		exit(1);
        }
}

void groupremoveuser(char **argv) {
	char *group;
	char *user;
        char **group_dn, **user_dn;

	group=argv[0];
	user=argv[1];

        group_dn=ad_search("name", group);
        if(ad_get_error_num()!=AD_SUCCESS) {
                fprintf(stderr, "error: %s\n", ad_get_error());
                exit(1);
        }

        user_dn=ad_search("name", user);
        if(ad_get_error_num()!=AD_SUCCESS) {
                fprintf(stderr, "error: %s\n", ad_get_error());
                exit(1);
        }

        if(ad_group_remove_user(*group_dn, *user_dn)!=AD_SUCCESS) {
                fprintf(stderr, "error removing user %s from group %s:\n%s",
                        *user_dn, *group_dn, ad_get_error());
		exit(1);
        }
}

void groupsubtreeremove(char **argv) {
	char *container;
	char *user;
        char **user_dn;

	container=argv[0];
	user=argv[1];

        user_dn=ad_search("name", user);
        if(ad_get_error_num()!=AD_SUCCESS) {
                fprintf(stderr, "error: %s\n", ad_get_error());
                exit(1);
        }

        if(ad_group_subtree_remove_user(container, *user_dn)!=AD_SUCCESS) {
                fprintf(stderr, "error removing user %s from subtree %s:\n%s",
                        *user_dn, container, ad_get_error());
		exit(1);
        }
}

void attributeget(char **argv) {
	char *object;
	char *attribute;
        int i;
        char **dn, **values;

	object=argv[0];
	attribute=argv[1];

        dn=ad_search("name", object);
        if(ad_get_error_num()!=AD_SUCCESS) {
                fprintf(stderr, "error: %s\n", ad_get_error());
                exit(1);
        }

        values=ad_get_attribute(*dn, attribute);
        if(ad_get_error_num()!=AD_SUCCESS) {
                fprintf(stderr, "error: %s\n", ad_get_error());
		exit(1);
        } 

	if(values!=NULL) {
                for(i=0; values[i]!=NULL; i++) {
                        printf("%s\n", values[i]);
                }
	}
}

void attributeadd(char **argv) {
	char *object;
	char *attribute;
	char *value;
        int result;
        char **dn;

	object=argv[0];
	attribute=argv[1];
	value=argv[2];

        dn=ad_search("name", object);
        if(ad_get_error_num()!=AD_SUCCESS) {
                fprintf(stderr, "error: %s\n", ad_get_error());
                exit(1);
        }

        result=ad_mod_add(*dn, attribute, value);
        if(result!=AD_SUCCESS) {
                fprintf(stderr, "error in attribute add: %s\n", ad_get_error());
		exit(1);
        }
}

void attributeaddbinary(char **argv) {
	char *object;
	char *attribute;
	char *filename;
        int result;
        char **dn;
        FILE *data_fd;
        struct stat data_stat;
        int filesize;
        char *data;

	object=argv[0];
	attribute=argv[1];
	filename=argv[2];

        dn=ad_search("name", object);
        if(ad_get_error_num()!=AD_SUCCESS) {
                fprintf(stderr, "error: %s\n", ad_get_error());
                exit(1);
        }

        data_fd=fopen(filename, "r");
        if(data_fd==NULL) {
                fprintf(stderr, "error: couldn't open file %s\n", filename);
                exit(1);
        }

        stat(filename, &data_stat);
        filesize=data_stat.st_size-1;
        data=malloc(filesize);
        fread(data, filesize, 1, data_fd);

        result=ad_mod_add_binary(*dn, attribute, data, filesize);
        if(result!=AD_SUCCESS) {
                fprintf(stderr, "error in attribute add: %s\n", ad_get_error());
		exit(1);
        }

        free(dn);
        free(data);
}

void attributereplace(char **argv) {
	char *object;
	char *attribute;
	char *value;
        int result;
        char **dn;

	object=argv[0];
	attribute=argv[1];
	value=argv[2];

        dn=ad_search("name", object);
        if(ad_get_error_num()!=AD_SUCCESS) {
                fprintf(stderr, "error: %s\n", ad_get_error());
                exit(1);
        }

        result=ad_mod_replace(*dn, attribute, value);
        if(result!=AD_SUCCESS) {
                fprintf(stderr, "error in attribute replace: %s\n", ad_get_error
());
		exit(1);
        }
}

void attributedelete(char **argv) {
	char *object;
	char *attribute;
	char *value;
        int result;
        char **dn;

	object=argv[0];
	attribute=argv[1];
	value=argv[2];

        dn=ad_search("name", object);
        if(ad_get_error_num()!=AD_SUCCESS) {
                fprintf(stderr, "error: %s\n", ad_get_error());
                exit(1);
        }

        result=ad_mod_delete(*dn, attribute, value);
        if(result!=AD_SUCCESS) {
                fprintf(stderr, "error in attribute replace: %s\n", ad_get_error
());
		exit(1);
        }
}

void search(char **argv) {
	char *attribute;
	char *value;
        char **results;
        int i;

	attribute=argv[0];
	value=argv[1];

        results=ad_search(attribute, value);
        if(results==(char **)-1) {
                fprintf(stderr, "Error: %s\n", ad_get_error());
                exit(1);
        }
        if(results!=NULL) {
                for(i=0; results[i]!=NULL; i++)
                        printf("%s\n", results[i]);
        }
}

void oucreate(char **argv) {
	char *ou, *container;
        int result, dn_length;
        char *dn;

	ou=argv[0];
	container=argv[1];

        dn_length=strlen(ou)+strlen(container)+5;
        dn=malloc(dn_length);
        snprintf(dn, dn_length, "ou=%s,%s", ou, container);
        result=ad_ou_create(ou, dn);
        if(result!=AD_SUCCESS) {
                fprintf(stderr, "error: %s\n", ad_get_error());
		exit(1);
        }
}

void oudelete(char **argv){
	char *ou;
        int result;
        char **dn;

	ou=argv[0];

        dn=ad_search("ou", ou);
        if(ad_get_error_num()!=AD_SUCCESS) {
                fprintf(stderr, "error: %s\n", ad_get_error());
                exit(1);
        }

        result=ad_object_delete(*dn);
        if(result!=AD_SUCCESS) {
                fprintf(stderr, "error, ou %s could not be deleted:\n%s\n", *dn, ad_get_error());
		exit(1);
        }
}

void list(char **argv) {
	char *dn;
	char **results;
	int i;

	dn=argv[0];

	results=ad_list(dn);
	if(results!=NULL) {
		for(i=0; results[i]!=NULL; i++) {
			printf("%s\n", results[i]);
		}
	}
}

struct function {
	char *name;
	void *operation;
	int num_args;
};

struct function function_table[] = {
	{"useradd", useradd, 2}, /* old name */
	{"usercreate", useradd, 2},

	{"userdelete", userdelete, 1},

	{"userlock", userlock, 1},

	{"userunlock", userunlock, 1},

	{"setpass", setpass, 1},

	{"usermove", usermove, 2},

	{"userrename", userrename, 2},

	{"computercreate", computercreate, 2},

	{"groupadd", groupadd, 2}, /* old name */
	{"groupcreate", groupadd, 2},

	{"groupdelete", groupdelete, 1},

	{"groupadduser", groupadduser, 2},

	{"groupremoveuser", groupremoveuser, 2},

	{"groupsubtreeremove", groupsubtreeremove, 2},

	{"attributeget", attributeget, 2},

	{"attributeadd", attributeadd, 3},

	{"attributeaddbinary", attributeaddbinary, 3},

	{"attributereplace", attributereplace, 3},

	{"attributedelete", attributedelete, 2},

	{"search", search, 2},

	{"oucreate", oucreate, 2},

	{"oudelete", oudelete, 1},

	{"list", list, 1}
};

int main(int argc, char **argv) {
	int c, i;
	int print_help=0;
	int print_version=0;
	char *operation_name;
	void (*operation)(char **);
	int num_functions;
	int num_args;

	while((c=getopt(argc, argv, "hvH:D:w:b:"))!=-1) {
		switch(c) {
			case 'h':
				print_help=1;
				break;
			case 'v':
				print_version=1;
				break;
			case 'H':
				uri=strdup(optarg);
				break;
			case 'D':
				binddn=strdup(optarg);
				break;
			case 'w':
				bindpw=strdup(optarg);
				memset(optarg, 0, strlen(optarg));
				break;
			case 'b':
				search_base=strdup(optarg);
		}
	}

	if(print_version) {
		printf("adtool version %s\n"
				"http://gp2x.org/adtool/\n"
				"by Mike Dawson <mike@gp2x.org>\n", 
				ADTOOL_VERSION);
		exit(0);
	}

	if(print_help||(argv[optind]==NULL)) {
		usage();
		exit(0);
	}

	operation_name=argv[optind];
	num_functions=(sizeof(function_table)/sizeof(struct function));
	num_args=0;
	operation=NULL;

	for(i=0; i<num_functions; i++) {
		if(!strcmp(operation_name, function_table[i].name)) {
			operation=function_table[i].operation;
			num_args=function_table[i].num_args;
			break;
		}
	}

	if(operation!=NULL && (argc-(optind+1))>=num_args) {
		(*operation)(argv+optind+1);
		exit(0);
	}

	usage();
	exit(1);
}
