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

#ifndef PAM_MOD_MISC_H
#define PAM_MOD_MISC_H

/*
 * All of this file has been taken from freebsd-lib and has been slightly
 * modified to avoid any problems when used on Linux machines. It provides
 * an easier logging interface and some additional options for OpenPAM.
 */


/*
 * Common option names
 */
#define	PAM_OPT_NULLOK		"nullok"
#define PAM_OPT_AUTH_AS_SELF	"auth_as_self"
#define PAM_OPT_ECHO_PASS	"echo_pass"
#define PAM_OPT_DEBUG		"debug"
//#define PAM_OPT_PRELIM_CHECK	"prelim_check"
//#define PAM_OPT_UPDATE_AUTHTOK	"update_authtok"
#define PAM_OPT_MD5		"md5"


#define	PAM_LOG(...) \
	openpam_log(PAM_LOG_DEBUG, __VA_ARGS__)

#define	PAM_ERROR(...) \
	openpam_log(PAM_LOG_ERROR, __VA_ARGS__)

#define PAM_RETURN(arg) \
	return (arg)

#define PAM_VERBOSE_ERROR(...) \
	_pam_verbose_error(pamh, flags, __FILE__, __FUNCTION__, __VA_ARGS__)

#endif
