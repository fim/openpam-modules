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

#define TTY_PREFIX      "/dev/"
#define SECURETTY 	"/etc/securetty"

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t * pamh, int flags,
		int argc, const char * argv[]) 
{
	struct passwd *pwd;
	struct stat ttyfileinfo;
	const char *user;
	const char *tty; 
	char ttyfileline[256];
	FILE *ttyfile;
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

	if ( pwd->pw_uid  != 0 ) { 
		/* secure tty applies only to root */
		return (PAM_SUCCESS);
	}

	if ( (pam_err = pam_get_item(pamh, PAM_TTY,(void *) &tty) ) != PAM_SUCCESS ) {
		PAM_ERROR("Could not determine user's tty");
		return (pam_err);
	}	

	if (tty != NULL && strncmp(TTY_PREFIX, tty, sizeof(TTY_PREFIX)) == 0) {
		PAM_LOG("tty starts with " TTY_PREFIX);
		/* get rid of prefix */
		tty = (const char *)tty + sizeof(TTY_PREFIX) - 1;
	}
	
	if ( stat(SECURETTY, &ttyfileinfo) ) { 
		PAM_ERROR("Could not open SECURETTY file :%s", SECURETTY);
		/* From LinuxPAM, they say that for compatibility issues, 
		 * this needs to succeed. */
		return (PAM_SUCCESS);
	}

	if ((ttyfileinfo.st_mode & S_IWOTH) || !S_ISREG(ttyfileinfo.st_mode)) {
		/* File is either world writable or not a regural file */
		PAM_ERROR("SECURETTY file cannot be trusted!");
		return (PAM_AUTH_ERR);
	}
	
	/* Open read-only file with securettys */
	if ( (ttyfile = fopen(SECURETTY,"r")) ==  NULL ) { 
		PAM_ERROR("Could not open SECURETTY file :%s", SECURETTY);
		return (PAM_AUTH_ERR);
	}

	pam_err = 1;
	/* Search in SECURETTY for tty */
	while (fgets(ttyfileline, sizeof(ttyfileline)-1, ttyfile) != NULL 
		&& pam_err) { 
	        if (ttyfileline[strlen(ttyfileline) - 1] == '\n')
	        	ttyfileline[strlen(ttyfileline) - 1] = '\0';

		pam_err = strcmp(ttyfileline, tty);

	}

	fclose(ttyfile);

	if (!pam_err) { 
		/* tty found in SECURETTY. Allow access */
		PAM_LOG("Access granted for %s on tty %s.", user, tty);
		return (PAM_SUCCESS); 
	}

	PAM_ERROR("Access denied: tty %s is not secure", tty);
	return (PAM_AUTH_ERR);
}


PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh , int flags ,
		int argc , const char *argv[])
{
	                return (PAM_SUCCESS);
}

PAM_MODULE_ENTRY("pam_securetty");
