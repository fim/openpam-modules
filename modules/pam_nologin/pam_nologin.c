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
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <pwd.h>

#define PAM_SM_AUTH

#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_mod_misc.h>

#define NOLOGIN "/etc/nologin"

PAM_EXTERN int 
pam_sm_authenticate( pam_handle_t *pamh, int flags, 
		int argc, const char * argv[] ) 
{
	struct passwd *pwd;
	struct stat st;
	char *mtmp = NULL;
	const char * user;
	int pam_err, fd; 

	if( (pam_err = pam_get_user(pamh,&user, NULL)) != PAM_SUCCESS ||
			(user == NULL) ) {
		PAM_ERROR("Could not determine user");
		return (PAM_USER_UNKNOWN);
	}

	fd = open(NOLOGIN, O_RDONLY, 0);
	/* 
	 * LinuxPAM's nologin returns PAM_IGNORE when no 'nologin' file is
	 * present while freebsd's nologin returns PAM_SUCCESS. We'll go 
	 * with PAM_IGNORE
	 * */

	if (fd < 0 )
		return (PAM_IGNORE);

	pwd = getpwnam(user);
	if(pwd && pwd->pw_uid == 0 )
		pam_err = PAM_SUCCESS;
	else { 
		if ( ! pwd ) 
			pam_err = PAM_USER_UNKNOWN;
	 	else 
			pam_err = PAM_AUTH_ERR;
	}

	/* get contents of /etc/nologin */
	if (fstat(fd,&st) < 0) { 
		close(fd);
		free(mtmp);
		return (pam_err);
	}


	mtmp = malloc(st.st_size + 1);
	if (!mtmp) {
		PAM_ERROR("Out of memory");
		close(fd);
		free(mtmp);
		return (PAM_BUF_ERR);
	}

	if ( read(fd, mtmp, st.st_size) == st.st_size ) {
		mtmp[st.st_size] = '\0';
		PAM_ERROR("%s", mtmp);
	} else 
		pam_err = PAM_SYSTEM_ERR;

	close(fd);
	free (mtmp);

	return (pam_err);

}	

PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh , int flags ,
		    int argc , const char *argv[])
{

	        return (PAM_SUCCESS);
}

PAM_MODULE_ENTRY("pam_nologin");
