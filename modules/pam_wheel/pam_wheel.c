/*
 * Copyright (c) 2008 Seraphim Mellos <mellos@ceid.upatras.gr>
 * 
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following
 * conditions:
 * 
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */ 

#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <string.h>
#include <grp.h>
#include <pwd.h>

#define PAM_SM_AUTH

#define PAM_OPT_ROOT_ONLY "root_only"

#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_mod_misc.h>

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t * pamh, int flags,
		int argc, const char * argv[]) 
{
	struct passwd *opwd,*tpwd;
	struct group *group;
	const char *orig_user, *target_user;
	char **user_list;
	int pam_err, member;

	/* Get info for target user. Who do you want to su to ? */

	if ( ( (pam_err = pam_get_user(pamh, &target_user, NULL)) != PAM_SUCCESS )
			|| ( orig_user == NULL ) )  {
		PAM_ERROR("Error recovering username.");	
		return (pam_err);
	}

	if ( (tpwd = getpwnam(target_user)) == NULL ) {
		PAM_ERROR("Could not get passwd entry for user [%s]",target_user);
		return (PAM_SERVICE_ERR);
	}
	
	if ( openpam_get_option(pamh, PAM_OPT_ROOT_ONLY) ) {
		/* if su to non-root -> ignore */
		if (tpwd->pw_uid != 0) 
			return (PAM_AUTH_ERR);
	}
	
	/* Get info for originating user. Who called su? */

	if ( ( (pam_err = pam_get_user(pamh, &orig_user, NULL)) != PAM_SUCCESS )
                        || ( orig_user == NULL ) )  {                                        
	        PAM_ERROR("Error recovering username.");
		return (pam_err);
	}

	if ( (opwd = getpwnam(orig_user)) == NULL ) {
		PAM_ERROR("Could not get passwd entry for user [%s]",orig_user);
		return (PAM_SERVICE_ERR);
	}
	
	/* We now have all user info we need */

	if ( (group = getgrnam("wheel")) == NULL ) { 
		group = getgrgid(0); 
	}
	
	/* Check wheel or group with GID 0 have any members */

	if (!group || (!group->gr_mem && (opwd->pw_gid != group->gr_gid))) {
		PAM_LOG("Group wheel or with GID 0 has no members");
		return (PAM_AUTH_ERR);
	}
	/* Check user's membership to the interested groups */
	member=0;
	user_list = group->gr_mem; 
	while ( !member && user_list && *(user_list) ) {
		if (strncmp(*user_list, orig_user, strlen(orig_user)-1 ) == 0) 
		            member=1;
		
		user_list++;
	}
	
	if ( member || ( opwd->pw_gid == group->gr_gid ) ) { 
		PAM_LOG("Access granted for user '%s' to user '%s'", orig_user, target_user);
		return (PAM_SUCCESS);
	} else { 
		PAM_ERROR("Access denied for user '%s' to user '%s'", orig_user, target_user);
		return (PAM_PERM_DENIED);
	}
}


PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh , int flags ,
                    int argc , const char *argv[])
{
	return (PAM_SUCCESS);
}

PAM_MODULE_ENTRY("pam_wheel");
