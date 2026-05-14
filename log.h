#ifndef _LOG_H
#define _LOG_H

#include <systemd/sd-journal.h>

#define LOG_EVENT(MSG, MSG_ID, MODULE_NAME) sd_journal_send("MESSAGE=%s", MSG, "MESSAGE_ID=%s", MSG_ID, "PRIORITY=%i", LOG_INFO, "MODULE=%s", MODULE_NAME, NULL)

#define KEY_DIGEST "Key digested successfully"
#define KEY_FLUSH "Key flushed successfully"
#define MODULE_STARTUP "Module activated successfully"
#define AUTH_FAIL "Authentication failed"
#define AUTH_SUCCESS "Authenticated successfully"
#define FILE_OPEN_FAIL "Failed to open requested file"
#define FILE_OPEN_SUCCESS "Requested file opened successfully"
#define INTEGRITY_CHECK_SUCCESS "File integrity check passed"
#define INTEGRITY_CHECK_FAIL "File integrity check failed"

static const char* MSG_ID_KEY_DIGEST = "e700336f59d54ea583ec7d5ade70e4db";
static const char* MSG_ID_KEY_FLUSH = "1ba72896418f4e3c9a5f0fe49423c767";
static const char* MSG_ID_MODULE_START = "3e83710374ac4f64891ee5f20fa9100f";
static const char* MSG_ID_AUTH_FAIL = "59f4956fb2144f5cbce318a7b9fabb8b";
static const char* MSG_ID_AUTH_SUCCESS = "8fdd5960ed8d46a8a10dd06d869b520e";
static const char* MSG_ID_OPEN_FAIL = "96478c224506464995ab7399f599c23f";
static const char* MSG_ID_OPEN_SUCCESS = "3e81b31542f54f95b82d49212144a3eb";
static const char* MSG_ID_INTEGRITY_SUCCESS = "99624b9569f2469291e129c0425c9271";
static const char* MSG_ID_INTEGRITY_FAIL = "d59d8cf2f87e4691a8c9c58fd5902197";

#endif // _LOG_H