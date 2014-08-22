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
#include <sys/stat.h>
#include <pwd.h>

#define PAM_SM_AUTH

#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_mod_misc.h>

#define SHELLS	"/etc/shells"

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t * pamh, int flags,
		int argc, const char * argv[]) 
{
	struct passwd *pwd;
	struct stat shellfileinfo;
	const char *user;
	const char *shell; 
	char shellfileline[256];
	FILE *shellfile;
	int pam_err;

	if ( ( (pam_err = pam_get_user(pamh, &user, NULL)) != PAM_SUCCESS ) 
			|| ( user == NULL ) )  {
		PAM_ERROR("Error recovering username.");
		return (pam_err);
	}

	if ( (pwd = getpwnam(user)) == NULL ) { 
		PAM_ERROR("Could not get passwd entry for user [%s]",user);
		return (PAM_SERVICE_ERR);
	}
	
	shell = pwd->pw_shell; 

	if ( stat(SHELLS, &shellfileinfo) ) { 
		PAM_ERROR("Could not open SHELLS file :%s", SHELLS);
		return (PAM_AUTH_ERR);
	}

	if ((shellfileinfo.st_mode & S_IWOTH) || !S_ISREG(shellfileinfo.st_mode)) {
		/* File is either world writable or not a regural file */
		PAM_ERROR("SHELLS file cannot be trusted!");
		return (PAM_AUTH_ERR);
	}
	
	/* Open read-only file with shells */
	if ( (shellfile = fopen(SHELLS,"r")) ==  NULL ) { 
		PAM_ERROR("Could not open SHELLS file :%s", SHELLS);
		return (PAM_SERVICE_ERR);
	}

	pam_err = 1;

	/* Search in SHELLS for user shell */
	while (fgets(shellfileline, sizeof(shellfileline)-1, shellfile) != NULL 
		&& pam_err) { 
	        if (shellfileline[strlen(shellfileline) - 1] == '\n')
	        	shellfileline[strlen(shellfileline) - 1] = '\0';

		pam_err = strcmp(shellfileline, shell);

	}

	fclose(shellfile);

	if (!pam_err) { 
		/* user shell found in SHELLS. Allow access */
		PAM_LOG("Access granted for %s with shell %s.", user, shell);
		return (PAM_SUCCESS); 
	}
	
	return (PAM_AUTH_ERR);
}


PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh , int flags ,
		int argc , const char *argv[])
{

	                return (PAM_SUCCESS);
}

PAM_MODULE_ENTRY("pam_shells");
