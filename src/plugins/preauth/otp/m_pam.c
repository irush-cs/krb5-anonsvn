/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * Copyright 2011 School of Computer Science and Engineering, Hebrew University
 * of Jerusalem.  All rights reserved.
 * Author: Yair Yarom <irush@cs.huji.ac.il>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *    1. Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *
 *    2. Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
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

/*
 * FAST OTP plugin method using simplified PAM backend
 * 
 * By default, the user is the principal name and the service is "krb5.<realm>"
 * (note that some pam implementation will put the service in lower case). If
 * the blob is available, then it contains <user>@<service> where both <user>
 * and <service> are optional (if no @, considered as service).
 */

#include <errno.h>

#include "otp.h"
#include "m_pam.h"

int otp_pam_get_user_service(const struct otp_req_ctx *ctx,
                             char** user,
                             char** service);

struct otp_pam_ctx {
    int a;
    //ykclient_t *yk_ctx;
};

static void
otp_pam_server_fini(void *method_context)
{
    struct otp_pam_ctx *ctx = method_context;
    free(ctx);
}

static int
otp_pam_verify_otp(const struct otp_req_ctx *otp_ctx, const char *pw)
{
    //struct otp_pam_ctx *ctx = OTP_METHOD_CONTEXT(otp_ctx);
    int ret = 0;
    //assert(otp_ctx != NULL);

    if (pw == NULL) {
        SERVER_DEBUG("[pam] password is missing.");
        return EINVAL;
    }
    
    return ret;
}

static int
otp_pam_challenge(const struct otp_req_ctx *ctx,
                  krb5_pa_otp_challenge *challenge) {
    char* user = NULL;
    char* service = NULL;
    int retval = 0;

    if (ctx->client == NULL) {
        SERVER_DEBUG("[pam] don't know who the the client is");
        return 1;
    }

    retval = otp_pam_get_user_service(ctx, &user, &service);
    if (retval != 0) {
        return retval;
    }


    if (challenge->otp_service.length != 0)
        free(challenge->otp_service.data);
    challenge->otp_service.data = strdup("hello");
    challenge->otp_service.length = strlen("hello") + 1;
    return retval;
}

int
otp_pam_server_init(struct otp_server_ctx *otp_ctx,
                    get_config_func_t get_config,
                    search_db_func_t search_db,
                    struct otp_method_ftable **ftable,
                    void **method_context)
{
    struct otp_method_ftable *ft = NULL;
    struct otp_pam_ctx *ctx = NULL;
    int retval = -1;
    ft = calloc(1, sizeof(*ft));
    if (ft == NULL) {
        retval = ENOMEM;
        goto errout;
    }
    ft->server_fini = otp_pam_server_fini;
    ft->server_verify = otp_pam_verify_otp;
    ft->server_challenge = otp_pam_challenge;
    ctx = calloc(1, sizeof(*ctx));
    if (ctx == NULL) {
        retval = ENOMEM;
        goto errout;
    }
    
    *ftable = ft;
    *method_context = ctx;
    return 0;

 errout:
    if (ft != NULL)
        free(ft);
    if (ctx != NULL)
        free(ctx);
    return retval;
}



/**
 * pam stuff
 */
int
otp_pam_get_user_service(const struct otp_req_ctx *ctx,
                         char** user,
                         char** service) {
    int len = 0;
    char* str = NULL;
    char* c;
    int retval = -1;
    *user = NULL;
    *service = NULL;

    if (ctx->blobsize > 0) {
        // will force a \0 terminated string
        str = calloc(1, ctx->blobsize + 1);
        if (str == NULL) {
            retval = ENOMEM;
            goto error;
        }
        memcpy(str, ctx->blob, ctx->blobsize);
        c = strchr(str, '@');
        if (c != NULL) {
            *c++ = 0;
            if (str[0] != 0) {
                *user = strdup(str);
                if (*user == NULL) {
                    retval = ENOMEM;
                    goto error;
                }
            }
        } else {
            c = str;
        }

        if (c[0] != 0) {
            *service = strdup(c);
            if (*service == NULL) {
                retval = ENOMEM;
                goto error;
            }
        }
    }

    if (*user == NULL) {
        len = krb5_princ_name(ctx->krb5_context, ctx->client->princ)->length;
        if ((*user = calloc(1, len + 1)) == NULL) {
            retval = ENOMEM;
            goto error;
        }
        strncpy(*user,
                krb5_princ_name(ctx->krb5_context, ctx->client->princ)->data,
                len);
    }

    if (*service == NULL) {
        len = krb5_princ_realm(ctx->krb5_context, ctx->client->princ)->length;
        if ((*service = calloc(1, len + 1 + 5)) == NULL) {
            retval = ENOMEM;
            goto error;
        }
        strcpy(*service, "krb5.");
        strncat(*service,
                krb5_princ_realm(ctx->krb5_context, ctx->client->princ)->data,
                len);
    }

    SERVER_DEBUG("[pam] got user: %s, service: %s, from %s", *user, *service,
                 (ctx->blobsize > 0 ? "blob" : "principal"));

    if (str != NULL)
        free(str);
    return 0;
    
 error:
    if (str != NULL)
        free(str);
    if (*user != NULL) {
        free(*user);
        *user = NULL;
    }
    if (*service != NULL) {
        free(*service);
        *service = NULL;
    }
    return retval;
}
