#ifndef _AUTH_H
#define _AUTH_H

#include <security/pam_appl.h>
#include <security/pam_misc.h>
#include <security/pam_ext.h>

int authenticate_user();
int my_conv(int num_msg, const pam_message **msg, pam_response **resp, void *appdata_ptr);

#endif // _AUTH_H