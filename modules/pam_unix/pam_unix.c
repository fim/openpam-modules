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

#include <pwd.h> 
#include <netdb.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <shadow.h>  
#include "md5.h"

#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_PASSWORD
#define PAM_SM_SESSION

#define MAX_RETRIES 		3
#define DEFAULT_WARN            (2L * 7L * 86400L) /* two weeks */


#include <security/pam_modules.h>
#include <security/pam_appl.h>
#include <security/openpam.h>
#include <security/pam_mod_misc.h>



/*
 * Helper functions for internal use
 */

static int update_shadow( pam_handle_t * pamh , 
		const char * user , const char * newhashedpwd );
static int update_passwd( pam_handle_t * pamh ,
		const char * user ,const char * newhashedpwd ); 
static char * read_shadow(const char * user) ; 

static void to64(char *s, long v, int n); 
void makesalt(char salt[SALTSIZE]);

/*
 * User authentication
 */

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags,
		int argc , const char *argv[] ) {
	struct passwd *pwd;
	const char *pass, *crypt_pass, *real_hash, *user;
	int pam_err;

	/* identify user */

	if (openpam_get_option(pamh, PAM_OPT_AUTH_AS_SELF)) {
		PAM_LOG("Authenticating as self.");
		pwd = getpwnam(getlogin());
	} else {
		if ((pam_err = pam_get_user(pamh, &user, NULL)) != PAM_SUCCESS) {
			PAM_ERROR("Authenticating with uname [%s] failed.", user);
	                return (pam_err);
		}

		pwd = getpwnam(user);
	}
	PAM_LOG("Authenticating user: [%s]", user);

	/* get password */

	if (pwd != NULL) {
		PAM_LOG("Doing real authentication");
		pass = pwd->pw_passwd; 
		if (pass[0] == '\0') {
			if (!(flags & PAM_DISALLOW_NULL_AUTHTOK) &&
					openpam_get_option(pamh, PAM_OPT_NULLOK)){
				PAM_LOG("User [%s] has empty password. \
						Authentication succesfull.", user);
				return (PAM_SUCCESS);
			}
		}			
		
		real_hash = "*";
		
	} else {
		PAM_LOG("Doing dummy authentication.");
		real_hash = "x";
	}

	pam_err = pam_get_authtok(pamh, PAM_AUTHTOK, (const char **) &pass, NULL);
	PAM_LOG("Got password for user [%s]", user);
        if (pam_err == PAM_CONV_ERR)
                return (pam_err);
	if (pam_err != PAM_SUCCESS)
	        return (PAM_AUTH_ERR);
	
	/* check passwd entry */

	if ( strncmp(real_hash, "x", sizeof(char)) != 0 ) {
		real_hash = read_shadow(user);
	}

	crypt_pass = crypt(pass,real_hash); 
	if ( strcmp(crypt_pass, real_hash) != 0 ) {
		PAM_ERROR("Wrong password. Authentication failed.");
		pam_err = PAM_AUTH_ERR;
	} else {
		PAM_LOG("Authentication completed succesfully.");
		pam_err = PAM_SUCCESS;
	}

	return (pam_err);
}

PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh , int flags ,
		    int argc , const char *argv[] ) {
	
	/* 
	 * This functions takes care of renewing/initializing
	 * user credentials as well as gid/uids. Someday, it
	 * will be completed. For now, it's not very urgent. 
	 */

	return (PAM_SUCCESS);
}


/*
 * Account Management
 */

PAM_EXTERN int
pam_sm_acct_mgmt(pam_handle_t *pamh, int flags ,
		    int argc , const char *argv[] ) {

	struct spwd *pwd;
	int pam_err;
	const char *user;
	time_t curtime;


	pam_err = pam_get_user(pamh, &user, NULL);

	if (pam_err != PAM_SUCCESS)
		return (pam_err);

	if (user == NULL || (pwd = getspnam(user)) == NULL)
		return (PAM_SERVICE_ERR);


	PAM_LOG("Got user [%s]" , user );
	
	if (*pwd->sp_pwdp == '\0' &&
         	(flags & PAM_DISALLOW_NULL_AUTHTOK) != 0)
		return (PAM_NEW_AUTHTOK_REQD);

	/* Calculate current time */
	curtime = time(NULL) / (60 * 60 * 24);
	
	/* Check for account expiration */
	if (pwd->sp_expire > 0) {
		if ( (curtime > pwd->sp_expire ) && ( pwd->sp_expire != -1 ) ) {
			PAM_ERROR("Account has expired!");
			return (PAM_ACCT_EXPIRED);
		} else if ( ( pwd->sp_expire - curtime < DEFAULT_WARN) ) {
			PAM_ERROR("Warning: your account expires on %s",
					ctime(&pwd->sp_expire));
		}
	

		if (pwd->sp_lstchg == 0 ) {
			return (PAM_NEW_AUTHTOK_REQD);
		}

		/* check all other possibilities (mostly stolen from pam_tcb) */
	
		if ((curtime > (pwd->sp_lstchg + pwd->sp_max + pwd->sp_inact)) &&
				(pwd->sp_max != -1) && (pwd->sp_inact != -1) &&
				(pwd->sp_lstchg != 0)) {
			PAM_ERROR("Account has expired!");
			return (PAM_ACCT_EXPIRED);
		}
	
		if (((pwd->sp_lstchg + pwd->sp_max) < curtime) &&
			        (pwd->sp_max != -1)) {
			PAM_ERROR("Account has expired!");
			return (PAM_ACCT_EXPIRED);
		}

		if ((curtime - pwd->sp_lstchg > pwd->sp_max)
				&& (curtime - pwd->sp_lstchg > pwd->sp_inact)
				&& (curtime - pwd->sp_lstchg > pwd->sp_max + pwd->sp_inact)
				&& (pwd->sp_max != -1) && (pwd->sp_inact != -1)) {
			PAM_ERROR("Account has expired!");
			return (PAM_ACCT_EXPIRED);
		}

	}

	pam_err = (PAM_SUCCESS);

	return (pam_err);

}

/*
 * Password Management
 */

PAM_EXTERN int 
pam_sm_chauthtok(pam_handle_t *pamh, int flags,
		int argc, const char *argv[]) 
{

	/* 
	 * NIS support will be left for future implementation.
	 * This is standard unix passwd changing function. 
	 */
	struct passwd  *old_pwd;
        const char *user, *old_pass, *new_pass;
        char  *hashedpwd,  salt[SALTSIZE+1];

	int pam_err, retries;
	
	/* identify user */

	if (openpam_get_option(pamh, PAM_OPT_AUTH_AS_SELF)) {
		PAM_LOG("Authenticating as self.");
		user=getlogin();
		old_pwd = getpwnam(user);
	} else {
		if ((pam_err = pam_get_user(pamh, &user, NULL)) != PAM_SUCCESS) {
			PAM_ERROR("Authenticating with uname [%s] failed.", user);
	                return (pam_err);
		}

	        old_pwd = getpwnam(user);
	}
	
	PAM_LOG("Got user: [%s]", user);

	if (old_pwd == NULL) {
		PAM_ERROR("User [%s] either has a corrupted passwd entry or \
				is not in the selected database", user);
                return (PAM_AUTHTOK_RECOVERY_ERR);
	}

	/*
	 * When looking through the LinuxPAM code, I came across this : 
	 *
	 * ` Various libraries at various times have had bugs related to
	 * '+' or '-' as the first character of a user name. Don't
	 * allow them. `
	 *
	 * I don't know if the problem is still around but just in case... 
	 */

	if (user == NULL || user[0] == '-' || user[0] == '+' ) { 
		PAM_ERROR("Bad username [%s]", user);
		return (PAM_USER_UNKNOWN);
	}



	if ( flags & PAM_PRELIM_CHECK ) {
		PAM_LOG("Doing preliminary actions.");
		if (getuid() == 0 ) { 
			/* root doesn't need old passwd */
			return (pam_set_item(pamh, PAM_OLDAUTHTOK, ""));
		}

		if ( (old_pwd->pw_passwd[0] == '\0' ) &&
			( openpam_get_option(pamh, PAM_OPT_NULLOK) ) && 
			!(flags & PAM_DISALLOW_NULL_AUTHTOK) ) {		
			/*
			 * Something funny could happen here since we don't 
			 * ask for a password.
			 */
			old_pass = "";
		} else { 
			pam_err = pam_get_authtok(pamh,PAM_OLDAUTHTOK, 
					&old_pass, NULL);
			if (pam_err != PAM_SUCCESS ) 
				return (pam_err);

		} 
		
		PAM_LOG("Got old token for user [%s].",user);
		
		hashedpwd = crypt(old_pass, old_pwd->pw_passwd);
		
		if (old_pass[0] == '\0' && !openpam_get_option(pamh, PAM_OPT_NULLOK))
			return (PAM_PERM_DENIED);
		
		if (strcmp(hashedpwd, old_pwd->pw_passwd) != 0)
			return (PAM_PERM_DENIED);

	} else if ( flags &  PAM_UPDATE_AUTHTOK )  {
		PAM_LOG("Doing actual update.");
		pam_err= pam_get_authtok(pamh, PAM_OLDAUTHTOK ,&old_pass, NULL);
                
		if (pam_err != PAM_SUCCESS)
			return (pam_err);
		
		PAM_LOG("Got old password");

		retries = 0;
		pam_err = PAM_AUTHTOK_ERR;

		while ((pam_err != PAM_SUCCESS) && ( retries++ <= MAX_RETRIES)) {
			
			pam_err = pam_get_authtok(pamh, PAM_AUTHTOK,
					&new_pass, NULL);

			PAM_ERROR("Unable to get new passwd. Please \
					 try again");

		}
		
		if (pam_err != PAM_SUCCESS) {
			PAM_ERROR("Unable to get new password!");
			return (pam_err);
		}

		PAM_LOG("Got new password");
		
		/* 
		 * checking has to be done (?) for the new passwd to 
		 * verify it's not weak. 
		 */
		
		if (getuid() != 0 && new_pass[0] == '\0' &&
				!openpam_get_option(pamh, PAM_OPT_NULLOK))
			return (PAM_PERM_DENIED);

		
		makesalt(salt);
		/* Update shadow/passwd entries for Linux */
		if ( openpam_get_option (pamh, PAM_OPT_MD5) ) {
			pam_err = update_shadow( pamh ,user, 
					MD5Hash(new_pass, salt)) ;
		} else { 

			pam_err = update_shadow( pamh ,user,
					crypt(new_pass, salt));
		}
	 	if ( pam_err != PAM_SUCCESS) 
			return (pam_err);

		pam_err = update_passwd( pamh ,user,"x");
		update_passwd( pamh ,user,"x");
		if ( pam_err != PAM_SUCCESS) 
			return (pam_err);
	
		PAM_LOG("Password changed for user [%s]", user);
	} else {
		pam_err = PAM_ABORT;
		PAM_ERROR("Unrecognized flags.");
		return (pam_err);
	}
	
	return (PAM_SUCCESS);
}


PAM_EXTERN int
pam_sm_open_session( pam_handle_t * pamh, int flags, 
		int argc, const char * argv[]) 
{
	char *user, *service;
	int pam_err;

	pam_err = pam_get_item(pamh, PAM_USER, (void *) &user);
	if ( pam_err != PAM_SUCCESS || user == NULL || *user == '\0') {
		PAM_ERROR("Open session - Error recovering username");
		return (PAM_SESSION_ERR);
	}

	pam_err = pam_get_item(pamh, PAM_SERVICE, (void *) &service);
	if ( pam_err != PAM_SUCCESS || service == NULL || *service == '\0') { 
		PAM_ERROR("Open session - Error recovering service");
		return (PAM_SESSION_ERR);
	}

	PAM_LOG("Opened session for user [%s] by %s(uid=%lu)", user, getlogin(), 
			(unsigned long) getuid());

	return PAM_SUCCESS;

}

PAM_EXTERN int
pam_sm_close_session( pam_handle_t * pamh, int flags, 
		int argc, const char * argv[]) 
{
	char *user, *service;
	int pam_err;
	pam_err = pam_get_item(pamh, PAM_USER, (void *) &user);
	if ( pam_err != PAM_SUCCESS || user == NULL || *user == '\0') {
		PAM_ERROR("Close session - Error recovering username");
		return (PAM_SESSION_ERR);
	}

	pam_err = pam_get_item(pamh, PAM_SERVICE, (void *) &service);
	if ( pam_err != PAM_SUCCESS || service == NULL || *service == '\0') { 
		PAM_ERROR("Close session - Error recovering service");
		return (PAM_SESSION_ERR);
	}

	PAM_LOG("Closed session for user [%s]", user);

	return PAM_SUCCESS;
}

#define NEW_SHADOW "/etc/.shadow"
/*
 * Update shadow with new user password
 */

static int update_shadow( pam_handle_t * pamh , const char * user,
		const char * newhashedpwd ) {
	FILE *oldshadow, *newshadow;
	struct spwd *pwd,*cur_pwd;
	struct stat filestat;


	if ( (pwd = getspnam(user)) == NULL) 
		return PAM_USER_UNKNOWN;

	if ( (oldshadow = fopen ("/etc/shadow", "r")) == NULL ) {
		PAM_ERROR("Could not open /etc/shadow. Updating shadow \
				database cancelled.");
		return (PAM_AUTHTOK_ERR);
	}

	if ( (newshadow = fopen (NEW_SHADOW, "w")) == NULL ) { 
		PAM_ERROR("Could not open temp file. Updating shadow \
				database cancelled.");
		fclose(oldshadow);
		return (PAM_AUTHTOK_ERR);
	} 
	
	if (fstat(fileno(oldshadow), &filestat) == -1 ) {
		PAM_ERROR("Could not get stat for /etc/shadow. \
				Updating shadow database cancelled.");
		fclose(oldshadow);
		fclose(newshadow);
		unlink(NEW_SHADOW);
		return (PAM_AUTHTOK_ERR);
	}

	if (fchown(fileno(newshadow), filestat.st_uid, filestat.st_gid) == -1 ) { 
		PAM_ERROR("Could not set uid/gid for new shadwow file. \
				Updating shadow database cancelled.");
		fclose(oldshadow);
		fclose(newshadow);
		unlink(NEW_SHADOW);
		return (PAM_AUTHTOK_ERR);
	}

	if (fchmod(fileno(newshadow), filestat.st_mode) == -1 ) { 
		PAM_ERROR("Could not chmod for new shadow file. \
				Updating shadow database cancelled.");
		fclose(oldshadow);
		fclose(newshadow);
		unlink(NEW_SHADOW);
		return (PAM_AUTHTOK_ERR);
	}

	while ( (cur_pwd = fgetspent(oldshadow)) ) { 
		if( strlen(user) == strlen(cur_pwd->sp_namp) 
				&& !strncmp(cur_pwd->sp_namp, user, strlen(user))) {
			cur_pwd->sp_pwdp = newhashedpwd; 
			cur_pwd->sp_lstchg = time(NULL) / (60 * 60 * 24);
			PAM_LOG("Updated password for user [%s]",user);
		}

		if(putspent(cur_pwd, newshadow)) { 
			PAM_ERROR("Error writing entry to new shadow file. \
					Updating shadow database cancelled.");
			fclose(oldshadow);
			fclose(newshadow);
			unlink(NEW_SHADOW);
			return (PAM_AUTHTOK_ERR);
		}
	}
	
	fclose(oldshadow);

	if (fclose(newshadow)) {
		PAM_ERROR("Error updating new shadow file.");
		unlink(NEW_SHADOW);
		return (PAM_AUTHTOK_ERR);
	}

	/* 
	 * If program flow has come up to here, all is good
	 * and it's safe to update the shadow file.
	 */

	if( rename(NEW_SHADOW, "/etc/shadow") == 0 ) {
		PAM_LOG("Password updated successfully for user [%s]",user);
	} else {
		PAM_ERROR("Error updating shadow file.");
		unlink(NEW_SHADOW);
		return (PAM_AUTHTOK_ERR);
	}
	
	return (PAM_SUCCESS);

}

/*
 * Update /etc/passwd with new user information
 */

#define NEW_PASSWD "/etc/.passwd"

static int update_passwd( pam_handle_t * pamh, const char * user,
		const char * newhashedpwd ) {
	FILE *oldpasswd, *newpasswd;
	struct passwd *pwd,*cur_pwd;
	struct stat filestat;


	if ( (pwd = getpwnam(user)) == NULL) 
		return PAM_USER_UNKNOWN;

	if ( (oldpasswd = fopen ("/etc/passwd", "r")) == NULL ) {
		PAM_ERROR("Could not open /etc/passwd. Updating passwd \
				database cancelled.");
		return (PAM_AUTHTOK_ERR);
	}

	if ( (newpasswd = fopen (NEW_PASSWD, "w")) == NULL ) { 
		PAM_ERROR("Could not open temp file. Updating passwd \
				database cancelled.");
		fclose(oldpasswd);
		return (PAM_AUTHTOK_ERR);
	} 
	
	if (fstat(fileno(oldpasswd), &filestat) == -1 ) {
		PAM_ERROR("Could not get stat for /etc/passwd. \
				Updating passwd database cancelled.");
		fclose(oldpasswd);
		fclose(newpasswd);
		unlink(NEW_PASSWD);
		return (PAM_AUTHTOK_ERR);
	}

	if (fchown(fileno(newpasswd), filestat.st_uid, filestat.st_gid) == -1 ) { 
		PAM_ERROR("Could not set uid/gid for new shadwow file. \
				Updating passwd database cancelled.");
		fclose(oldpasswd);
		fclose(newpasswd);
		unlink(NEW_PASSWD);
		return (PAM_AUTHTOK_ERR);
	}

	if (fchmod(fileno(newpasswd), filestat.st_mode) == -1 ) { 
		PAM_ERROR("Could not chmod for new passwd file. \
				Updating passwd database cancelled.");
		fclose(oldpasswd);
		fclose(newpasswd);
		unlink(NEW_PASSWD);
		return (PAM_AUTHTOK_ERR);
	}

	while ( (cur_pwd = fgetpwent(oldpasswd)) ) { 
		if( strlen(user) == strlen(cur_pwd->pw_name) 
				&& !strncmp(cur_pwd->pw_name, user, strlen(user))) {
			cur_pwd->pw_passwd = newhashedpwd; 
			PAM_LOG("Updated password for user [%s]",user);
		}

		if(putpwent(cur_pwd, newpasswd)) { 
			PAM_ERROR("Error writing entry to new passwd file. \
					Updating passwd database cancelled.");
			fclose(oldpasswd);
			fclose(newpasswd);
			unlink(NEW_PASSWD);
			return (PAM_AUTHTOK_ERR);
		}
	}
	
	fclose(oldpasswd);

	if (fclose(newpasswd)) {
		PAM_ERROR("Error updating new passwd file.");
		unlink(NEW_PASSWD);
		return (PAM_AUTHTOK_ERR);
	}

	/* 
	 * If program flow has come up to here, all is good
	 * and it's safe to update the passwd file.
	 */

	if( rename(NEW_PASSWD, "/etc/passwd") == 0 ) {
		PAM_LOG("Password updated successfully for user [%s]",user);
	} else {
		PAM_ERROR("Error updating passwd file.");
		unlink(NEW_PASSWD);
		return (PAM_AUTHTOK_ERR);
	}
	
	return (PAM_SUCCESS);

}


/* 
 * Read hashed password for user from shadow entry.
 * This is for use on Linux machines only.
 */
static char * read_shadow(const char * user) { 

	struct spwd * pwd;
	/* 
	 * No error checking. Everything has been tested prior to 
	 * calling this function. Nothing can go wrong, right?
	 */
	pwd = getspnam(user);

	return (pwd->sp_pwdp);
}

PAM_MODULE_ENTRY("pam_unix")
