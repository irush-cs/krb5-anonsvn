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

/* FAST OTP plugin method using simplified PAM backend  */

#include <errno.h>

#include "otp.h"
#include "m_pam.h"

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
otp_pam_verify_otp(const struct otp_server_ctx *otp_ctx, const char *pw)
{
    struct otp_pam_ctx *ctx = OTP_METHOD_CONTEXT(otp_ctx);
    int ret = 0;
    //assert(otp_ctx != NULL);

    if (pw == NULL) {
        SERVER_DEBUG("[pam] password is missing.");
        return EINVAL;
    }
    
    return ret;
}

static int
otp_pam_challenge(const struct otp_server_ctx *ctx,
                  krb5_pa_otp_challenge *challenge) {
    if (challenge->otp_service.length != 0)
        free(challenge->otp_service.data);
    challenge->otp_service.data = strdup("hello");
    challenge->otp_service.length = strlen("hello") + 1;
    return 0;
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
