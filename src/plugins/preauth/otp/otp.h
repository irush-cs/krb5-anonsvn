/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * Copyright (C) 2011 NORDUnet A/S.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Red Hat, Inc., nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER
 * OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
//#include <stddef.h>
#include <krb5/krb5.h>
#include <kdb.h>
#include "adm_proto.h"          /* for krb5_klog_syslog */

#ifdef DEBUG
#include <syslog.h>             /* for LOG_* */
#define SERVER_DEBUG(body, ...) krb5_klog_syslog(LOG_DEBUG, "OTP PA: "body, \
                                                 ##__VA_ARGS__)
#define CLIENT_DEBUG(body, ...) fprintf(stderr, "OTP PA: "body, ##__VA_ARGS__)
#else
#define SERVER_DEBUG(body, ...)
#define CLIENT_DEBUG(body, ...)
#endif

struct otp_method_ftable;
struct otp_tlv;
struct otp_server_ctx;

typedef int
(*search_db_func_t)(void *krb_ctx,
                    int search,
                    void **state,
                    struct otp_tlv **tlv_out);

typedef char *
(*get_config_func_t)(struct otp_server_ctx *otp_ctx,
                     const char *realm,
                     const char *str);

typedef int
(*otp_server_init_func_t)(struct otp_server_ctx *context,
                          get_config_func_t get_config,
                          search_db_func_t search_db,
                          struct otp_method_ftable **ftable,
                          void **method_context);
typedef void
(*otp_server_fini_func_t)(void *method_context);

/** Function verifying an OTP.  Returns 0 on successful verification.  */
typedef int
(*otp_server_verify_func_t)(const struct otp_server_ctx *ctx, const char *pw);


struct otp_tlv {
    unsigned int type;
    size_t length;
    void *value;
};

struct otp_method_ftable {
    /** Fini function invoked when the OTP plugin is unloaded.  */
    otp_server_fini_func_t server_fini; /* FIXME: Don't use krb5 struct. */
    /** Verification function, see \a otp_server_verify_func_t.  */
    otp_server_verify_func_t server_verify;
};

struct otp_method {
    char *name;
    otp_server_init_func_t init;
    char enabled_flag;
    void *context;
    struct otp_method_ftable *ftable;
};

struct otp_client_ctx {
    char *otp;
};

struct otp_server_ctx {
#ifdef DEBUG
#define MAGIC_OTP_SERVER_CTX 0xbeef4711
    unsigned int magic;
#endif
    krb5_context krb5_context;
    char *token_id;
    char *blob;
    size_t blobsize;
    /** Saved by server_get_edata() for later use by search_db().  */
    krb5_db_entry *client; /* struct _krb5_db_entry_new */
    /** Authentication method currently in use.  */
    struct otp_method *method;
};
