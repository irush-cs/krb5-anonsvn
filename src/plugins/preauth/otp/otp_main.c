/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * Copyright (C) 2006 Red Hat, Inc.
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

/*
  A successful OTP authentication follows this process on the KDC.

  (1) The kdb is searched for an OTP token identity, matching what
      might be found in preauth attribute "OTP_TOKENID".

  (2) An authentication method, i.e. a function, is picked from the
      result of (1).

  (3) The authentication method from (2) is invoked with a potential
      data blob found in (1).

  (4) The result from (3) is returned.

  OTP info per principal is stored in the kdb using the
  KRB5_TL_STRING_ATTRS tl-data type.  The keyword used is "otp-token".
  The format of the value is

    <otp-token-id>:<method-name>:<data-blob>

    otp-token-id identifies a unique token on the form of a class A
    OATH token identifier as specified in
    http://www.openauthentication.org/oath-id: MMTTUUUUUUUU, where
    M=manufacturer, T=token type and U=manufacturer unique id.

    method-name identifies the method to use for authentication
    (f.ex. "basicauth", "ykclient" or "nativehotp").  The method name
    maps to a function in the OTP plugin or possibly in a second-level
    plugin.  A method may use the prefix "otp_<method-name>_" for
    profile names in krb5.conf.

    data-blob is a binary blob passed to the authentication method
    chosen based on method-name.

  A token id may be passed to the KDC using the pre-authentication
  attribute OTP_TOKENID ("kinit -X OTP_TOKENID=mytoken ...").  If no
  OTP_TOKENID is provided, the first token id found is being used.  */

#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <assert.h>

#include "../lib/krb5/asn.1/asn1_encode.h"
#include <krb5/preauth_plugin.h>
#include "../fast_factor.h"


/* FIXME: Belong in krb5.hin.  */
#define KRB5_KEYUSAGE_PA_OTP_REQUEST 		45
#define KRB5_PADATA_OTP_CHALLENGE  141
#define KRB5_PADATA_OTP_REQUEST    142
#define KRB5_PADATA_OTP_CONFIRM    143
#define KRB5_PADATA_OTP_PIN_CHANGE 144

#define OTP_FLAG_RESERVED 0
#define OTP_FLAG_NEXT_OTP (1u<<1)
#define OTP_FLAG_COMBINE (1u<<2)
#define OTP_FLAG_PIN_REQUIRED (1u<<3)
#define OTP_FLAG_PIN_NOT_REQUIRED (1u<<4)
#define OTP_FLAG_MUST_ENCRYPT_NONCE (1u<<5)

/* A (class A) OATH token identifier as specified in
   http://www.openauthentication.org/oath-id: MMTTUUUUUUUU.
   M=manufacturer, T=token type, U=manufacturer unique id.  */
#define TOKEN_ID_LENGTH 12

#include "otp.h"
#include "m_basicauth.h"
#include "m_ykclient.h"

/* Configured OTP methods.  */
struct otp_method otp_methods[] = {
    {"basicauth", otp_basicauth_server_init, 0, NULL, NULL},
    {NULL, NULL, 0, NULL, NULL}
};


/************/
/* Client.  */
static krb5_preauthtype otp_client_supported_pa_types[] = {
    KRB5_PADATA_OTP_CHALLENGE,
    0
};

static int
otp_client_init(krb5_context context, krb5_clpreauth_moddata *moddata_out)
{
    struct otp_client_ctx *ctx = NULL;

    ctx = calloc(1, sizeof(*ctx));
    if (ctx == NULL) {
        return ENOMEM;
    }
    *moddata_out = (krb5_clpreauth_moddata) ctx;
    return 0;
}

static void
otp_client_fini(krb5_context context, krb5_clpreauth_moddata moddata)
{
    struct otp_client_ctx *ctx = (struct otp_client_ctx *) moddata;

    if (ctx == NULL) {
        return;
    }
    free(ctx->otp);
    free(ctx);
}

static int
otp_client_get_flags(krb5_context context, krb5_preauthtype pa_type)
{
    return PA_REAL;
}

static krb5_error_code
otp_client_gic_opts(krb5_context context,
                    krb5_clpreauth_moddata moddata,
                    krb5_get_init_creds_opt *gic_opt,
                    const char *attr,
                    const char *value)
{
    struct otp_client_ctx *otp_ctx = (struct otp_client_ctx *) moddata;

    if (otp_ctx == NULL) {
        CLIENT_DEBUG("Missing context.\n");
        return KRB5_PREAUTH_FAILED;
    }

    if (strcmp(attr, "OTP") == 0) {
        if (otp_ctx->otp != NULL) {
            krb5_set_error_message(context, KRB5_PREAUTH_FAILED,
                                   "OTP can not be given twice.\n");
            return KRB5_PREAUTH_FAILED;
        }

        otp_ctx->otp = strdup(value);
        if (otp_ctx->otp == NULL) {
            krb5_set_error_message(context, KRB5_PREAUTH_FAILED,
                                   "Unable to copy OTP.\n");
            return ENOMEM;
        }

        CLIENT_DEBUG("Got OTP [%s].\n", otp_ctx->otp);
    }

    return 0;
}

static krb5_error_code
otp_client_process(krb5_context context,
                   krb5_clpreauth_moddata moddata,
                   krb5_clpreauth_modreq modreq,
                   krb5_get_init_creds_opt *opt,
                   krb5_clpreauth_get_data_fn get_data,
                   krb5_clpreauth_rock rock,
                   krb5_kdc_req *request,
                   krb5_data *encoded_request_body,
                   krb5_data *encoded_previous_request,
                   krb5_pa_data *padata,
                   krb5_prompter_fct prompter,
                   void *prompter_data,
                   krb5_clpreauth_get_as_key_fn gak_fct,
                   void *gak_data,
                   krb5_data *salt,
                   krb5_data *s2kparams,
                   krb5_keyblock *as_key,
                   krb5_pa_data ***out_padata)
{
    krb5_error_code retval = 0;
    krb5_keyblock *armor_key = NULL;
    krb5_pa_data *pa = NULL;
    krb5_pa_data **pa_array = NULL;
    struct otp_client_ctx *otp_ctx = (struct otp_client_ctx *) moddata;
    krb5_pa_otp_req otp_req;
    krb5_data *encoded_otp_req = NULL;
    krb5_pa_otp_challenge *otp_challenge = NULL;
    krb5_data encoded_otp_challenge;

    retval = fast_get_armor_key(context, get_data, rock, &armor_key);
    if (retval != 0 || armor_key == NULL) {
        CLIENT_DEBUG("Missing armor key.\n");
        goto errout;
    }

    krb5_free_keyblock_contents(context, as_key);
    retval = krb5_copy_keyblock_contents(context, armor_key, as_key);
    krb5_free_keyblock(context, armor_key);
    if (retval != 0) {
        CLIENT_DEBUG("krb5_copy_keyblock_contents failed.\n");
        goto errout;
    }

    CLIENT_DEBUG("Got [%d] bytes padata type [%d].\n", padata->length,
                 padata->pa_type);

    if (padata->pa_type == KRB5_PADATA_OTP_CHALLENGE) {
        if (padata->length != 0) {
            encoded_otp_challenge.data = (char *) padata->contents;
            encoded_otp_challenge.length = padata->length;
            retval = decode_krb5_pa_otp_challenge(&encoded_otp_challenge,
                                                  &otp_challenge);
            if (retval != 0) {
                goto errout;
            }
        }

        if (otp_challenge->nonce.data == NULL) {
            CLIENT_DEBUG("Missing nonce in OTP challenge.\n");
            retval = EINVAL;
            goto errout;
        }

        memset(&otp_req, 0, sizeof(otp_req));

        retval = krb5_c_encrypt_length(context, as_key->enctype,
                                       otp_challenge->nonce.length,
                                       (size_t *) &otp_req.enc_data.ciphertext.length);
        if (retval != 0) {
            CLIENT_DEBUG("krb5_c_encrypt_length failed.\n");
            goto errout;
        }

        otp_req.enc_data.ciphertext.data =
            (char *) malloc(otp_req.enc_data.ciphertext.length);
        if (otp_req.enc_data.ciphertext.data == NULL) {
            CLIENT_DEBUG("Out of memory.\n");
            retval = ENOMEM;
            goto errout;
        }

        retval = krb5_c_encrypt(context, as_key, KRB5_KEYUSAGE_PA_OTP_REQUEST,
                                NULL, &otp_challenge->nonce, &otp_req.enc_data);
        if (retval != 0) {
            CLIENT_DEBUG("Failed to encrypt nonce.\n");
            goto errout;
        }

        pa = calloc(1, sizeof(krb5_pa_data));
        if (pa == NULL) {
            retval = ENOMEM;
            goto errout;
        }

        pa_array = calloc(2, sizeof(krb5_pa_data *));
        if (pa_array == NULL) {
            retval = ENOMEM;
            goto errout;
        }

        if (otp_ctx->otp == NULL) {
            CLIENT_DEBUG("Missing client context.\n");
        } else {
            otp_req.otp_value.data = otp_ctx->otp;
            otp_req.otp_value.length = strlen(otp_ctx->otp);
        }

        retval = encode_krb5_pa_otp_req(&otp_req, &encoded_otp_req);
        if (retval != 0) {
            CLIENT_DEBUG("encode_krb5_pa_otp_req failed.\n");
            goto errout;
        }

        pa->length = encoded_otp_req->length;
        pa->contents = (unsigned char *) encoded_otp_req->data;
        pa->pa_type = KRB5_PADATA_OTP_REQUEST;

        pa_array[0] = pa;
        pa = NULL;
        *out_padata = pa_array;
        pa_array = NULL;
    } else {
        CLIENT_DEBUG("Unexpected PA data.\n");
        retval = EINVAL;
        goto errout;
    }

    CLIENT_DEBUG("Successfully processed PA data.\n");
    return 0;

 errout:
    free(pa_array);
    free(pa);
    return retval;
}

krb5_error_code
clpreauth_otp_initvt(krb5_context context, int maj_ver, int min_ver,
                     krb5_plugin_vtable vtable);

krb5_error_code
clpreauth_otp_initvt(krb5_context context, int maj_ver, int min_ver,
                     krb5_plugin_vtable vtable)
{
    krb5_clpreauth_vtable vt;

    if (maj_ver != 1) {
        return KRB5_PLUGIN_VER_NOTSUPP;
    }
    vt = (krb5_clpreauth_vtable) vtable;
    vt->name = "otp";
    vt->pa_type_list = otp_client_supported_pa_types;
    vt->init = otp_client_init;
    vt->fini = otp_client_fini;
    vt->flags = otp_client_get_flags;
    vt->process = otp_client_process;
    vt->gic_opts = otp_client_gic_opts;
    return 0;
}


/************/
/* Server.  */
static int
otp_server_get_flags(krb5_context kcontext, krb5_preauthtype pa_type)
{
    return PA_HARDWARE | PA_REPLACES_KEY;
}


/* Free a request context. */
static void
otp_server_free_req_ctx(struct otp_req_ctx **request)
{
    if (*request == NULL)
        return;
    free((*request)->token_id);
    free((*request)->blob);
    free(*request);
    *request = NULL;
}

/* Find OTP info for principal in kdb.  */
static int
otp_server_find_token(struct otp_server_ctx *ctx,
                      struct _krb5_db_entry_new *client,
                      char **token_id_out,
                      char **method_name_out,
                      char **blob_out)
{
    krb5_error_code retval = 0;
    krb5_string_attr *strs = NULL;
    int n_strs = 0;
    char *found_string = NULL;
    char *method_name = NULL;
    char *blob = NULL;

    *token_id_out = NULL;
    *method_name_out = NULL;
    *blob_out = NULL;

    found_string = NULL;
    retval = krb5_dbe_get_strings(ctx->krb5_context, client, &strs, &n_strs);
    if (retval == 0) {
        while (--n_strs >= 0) {
            if (strncmp(strs[n_strs].key, "otp-token",
                        sizeof("otp-token")) == 0) {
                /* TODO: Match key against PA attribute "OTP_TOKENID".
                   Use TOKEN_ID_LENGTH.  */
                found_string = strs[n_strs].value;
                break;
            }
        }
    }
    if (found_string != NULL) {
        /* <otp-token-id>:<method-name>:<data-blob> */
        method_name = strchr(found_string, ':');
        if (method_name != NULL) {
            *method_name++ = '\0';
            blob = strchr(method_name, ':');
            if (blob != NULL) {
                *blob++ = '\0';
                *blob_out = strdup(blob);
                if (*blob_out == NULL) {
                    retval = ENOMEM;
                    goto errout;
                }
            }
            *method_name_out = strdup(method_name);
            if (*method_name_out == NULL) {
                retval = ENOMEM;
                goto errout;
            }
            *token_id_out = strdup(found_string);
            if (*token_id_out == NULL) {
                retval = ENOMEM;
                goto errout;
            }
        }
    }
    krb5_dbe_free_strings(ctx->krb5_context, strs, n_strs);
    return 0;

 errout:
    krb5_dbe_free_strings(ctx->krb5_context, strs, n_strs);
    free(*token_id_out);
    *token_id_out = NULL;
    free(*method_name_out);
    *method_name_out = NULL;
    free(*blob_out);
    *blob_out = NULL;
    return retval;
}

/* Create a request context with the client, blob, token and method, to use in
   the server edata and verify methods. */
static int
otp_server_create_req_ctx(struct otp_server_ctx *ctx,
                          struct _krb5_db_entry_new *client,
                          struct otp_req_ctx **request_out)
{
    krb5_error_code retval = 0;
    char *method_name = NULL;
    int f;

    *request_out = calloc(1, sizeof(struct otp_req_ctx));
    if (*request_out == NULL) {
        return ENOMEM;
    }
    (*request_out)->client = client;

    retval = otp_server_find_token(ctx,
                                   client,
                                   &((*request_out)->token_id),
                                   &method_name,
                                   &((*request_out)->blob));
    if (retval != 0) {
        SERVER_DEBUG("Error getting OTP info for principal: %d.", retval);
        goto errout;
    }

    if ((*request_out)->token_id == NULL) {
        SERVER_DEBUG("Token id not found for principal.");
        retval = ENOENT;
        goto errout;
    }

    if (method_name == NULL) {
        SERVER_DEBUG("Authentication method not set for principal.");
        retval = ENOENT;
        goto errout;
    }

    for (f = 0; otp_methods[f].name != NULL; f++) {
        if (strcmp(otp_methods[f].name, method_name) == 0) {
            (*request_out)->method = &otp_methods[f];
        }
    }
    if ((*request_out)->method == NULL) {
        SERVER_DEBUG("Authentication method %s not configured.", method_name);
        retval = ENOENT;
        goto errout;
    }

    SERVER_DEBUG("Token id [%s] found; method [%s], blob [%s].",
                 (*request_out)->token_id,
                 method_name,
                 (*request_out)->blob ? (*request_out)->blob : "");
    free(method_name);
    return 0;

 errout:
    otp_server_free_req_ctx(request_out);
    free(method_name);
    return retval;
}

static char *
get_config(struct otp_server_ctx *otp_ctx,
           const char *realm_in,
           const char *str)
{
    krb5_context k5_ctx = NULL;
    krb5_error_code retval = 0;
    char *result = NULL;
    const char *realm = realm_in;
    assert(otp_ctx != NULL);

    k5_ctx = otp_ctx->krb5_context;
    assert(k5_ctx != NULL);

    if (realm == NULL) {
        realm = k5_ctx->default_realm;
    }
    retval = profile_get_string(k5_ctx->profile, KRB5_CONF_REALMS, realm, str,
                                NULL, &result);
    if (retval != 0) {
        SERVER_DEBUG("%s: profile_get_string error: %d.", __func__, retval);
        result = NULL;
    }

    return result;
}

static void
server_init_methods(struct otp_server_ctx *ctx)
{
    int f;
    int err;

    for (f = 0; otp_methods[f].name != NULL; f++) {
        struct otp_method *m = &otp_methods[f];
        err = m->init(ctx,
                      get_config,
                      NULL,   /* FIXME: remove (was search_db_type) */
                      &m->ftable,
                      &m->context);
        if (err == 0) {
            m->enabled_flag = 1;
        }
        else {
            SERVER_DEBUG("Failing init for method [%s], error %d.", m->name,
                         err);
        }
    }
}

static krb5_error_code
otp_server_init(krb5_context krb5_ctx,
                krb5_kdcpreauth_moddata *moddata_out,
                const char **realmnames)
{
    struct otp_server_ctx *ctx = NULL;
    krb5_error_code retval = 0;

    assert(moddata_out != NULL);

    ctx = calloc(1, sizeof(*ctx));
    if (ctx == NULL) {
        retval = ENOMEM;
        goto errout;
    }
#ifdef DEBUG
    ctx->magic = MAGIC_OTP_SERVER_CTX;
#endif

    ctx->krb5_context = krb5_ctx;
    server_init_methods(ctx);
    *moddata_out = (krb5_kdcpreauth_moddata) ctx;

    return 0;

 errout:
    free (ctx);
    return retval;
}

static void
server_fini_methods(struct otp_server_ctx *ctx)
{
    int f;

    for (f = 0; otp_methods[f].name != NULL; f++) {
        struct otp_method *m = &otp_methods[f];
        if (m->enabled_flag) {
            assert(m->ftable);
            if (m->ftable->server_fini) {
                m->ftable->server_fini(m->context);
            }
            free (m->ftable);
        }
    }
}

static void
otp_server_fini(krb5_context context, krb5_kdcpreauth_moddata moddata)
{
    struct otp_server_ctx *ctx = (struct otp_server_ctx *) moddata;
    assert(ctx != NULL);

    server_fini_methods(ctx);
    free(ctx);
}

static krb5_error_code
otp_server_get_edata(krb5_context context,
                     krb5_kdc_req *request,
                     struct _krb5_db_entry_new *client,
                     struct _krb5_db_entry_new *server,
                     krb5_kdcpreauth_get_data_fn get_entry_data,
                     krb5_kdcpreauth_moddata moddata,
                     krb5_pa_data *pa_data_out)
{
    krb5_error_code retval = -1;
    krb5_keyblock *armor_key = NULL;
    krb5_pa_otp_challenge otp_challenge;
    krb5_data *encoded_otp_challenge = NULL;
    struct otp_server_ctx *otp_ctx = (struct otp_server_ctx *) moddata;
    krb5_timestamp now_sec;
    krb5_int32 now_usec;

    assert(otp_ctx != NULL);
    memset(&otp_challenge, 0, sizeof(otp_challenge));

    retval = fast_kdc_get_armor_key(context, get_entry_data, request, client,
                                    &armor_key);
    if (retval != 0 || armor_key == NULL) {
        SERVER_DEBUG("No armor key found.");
        retval = EINVAL;
        goto errout;
    }

    /* Create nonce from random data + timestamp.  Length of random
       data equals the length of the server key.  The timestamp is 4
       octets current time, seconds since the epoch and 4 bytes
       microseconds, both encoded in network byte order.  */
    otp_challenge.nonce.length = armor_key->length + 8;
    otp_challenge.nonce.data = (char *) malloc(otp_challenge.nonce.length);
    if (otp_challenge.nonce.data == NULL) {
        retval = ENOMEM;
        goto errout;
    }
    retval = krb5_c_random_make_octets(context, &otp_challenge.nonce);
    if (retval != 0) {
        SERVER_DEBUG("Unable to create random data for nonce.");
        goto errout;
    }
    if (krb5_us_timeofday(context, &now_sec, &now_usec) != 0) {
        SERVER_DEBUG("Unable to get current time.");
        retval = KRB5KDC_ERR_PREAUTH_FAILED;
        goto errout;
    }
    *((uint32_t *) (otp_challenge.nonce.data + armor_key->length)) =
        htonl(now_sec);
    *((uint32_t *) (otp_challenge.nonce.data + armor_key->length + 4)) =
        htonl(now_usec);

    /* otp_challenge.otp_keyinfo.flags |= FIXME->keyinfo_flags; */
    otp_challenge.otp_keyinfo.flags = -1;

    /* Encode challenge.  */
    retval = encode_krb5_pa_otp_challenge(&otp_challenge,
                                          &encoded_otp_challenge);
    if (retval != 0) {
        SERVER_DEBUG("Unable to encode challenge.");
        goto errout;
    }

    pa_data_out->pa_type = KRB5_PADATA_OTP_CHALLENGE;
    pa_data_out->contents = (krb5_octet *) encoded_otp_challenge->data;
    pa_data_out->length = encoded_otp_challenge->length;

    return 0;

 errout:
    krb5_free_keyblock(context, armor_key);
    return retval;
}

static krb5_error_code
otp_server_verify(krb5_context context,
                  struct _krb5_db_entry_new *client,
                  krb5_data *req_pkt,
                  krb5_kdc_req *request,
                  krb5_enc_tkt_part *enc_tkt_reply,
                  krb5_pa_data *data,
                  krb5_kdcpreauth_get_data_fn get_entry_data,
                  krb5_kdcpreauth_moddata moddata,
                  krb5_kdcpreauth_modreq *modreq_out,
                  krb5_data **e_data,
                  krb5_authdata ***authz_data)
{
    krb5_pa_otp_req *otp_req = NULL;
    krb5_error_code retval = KRB5KDC_ERR_PREAUTH_FAILED;
    krb5_data encoded_otp_req;
    char *otp = NULL;
    int ret;
    krb5_keyblock *armor_key = NULL;
    krb5_data decrypted_data;
    struct otp_server_ctx *otp_ctx = (struct otp_server_ctx *) moddata;
    struct otp_req_ctx *otp_req_ctx = NULL;
    krb5_timestamp now_sec, ts_sec;
    krb5_int32 now_usec, ts_usec;

    assert(otp_ctx != NULL);

    encoded_otp_req.length = data->length;
    encoded_otp_req.data = (char *) data->contents;

    retval = decode_krb5_pa_otp_req(&encoded_otp_req, &otp_req);
    if (retval != 0) {
        SERVER_DEBUG("Unable to decode OTP request.");
        retval = KRB5KDC_ERR_PREAUTH_FAILED;
        goto errout;
    }

    if (otp_req->enc_data.ciphertext.data == NULL) {
        SERVER_DEBUG("Missing encData in PA-OTP-REQUEST.");
        retval = KRB5KDC_ERR_PREAUTH_FAILED;
        goto errout;
    }

    decrypted_data.length = otp_req->enc_data.ciphertext.length;
    decrypted_data.data = (char *) malloc(decrypted_data.length);
    if (decrypted_data.data == NULL) {
        SERVER_DEBUG("malloc failed.");
        retval = ENOMEM;
        goto errout;
    }

    retval = fast_kdc_get_armor_key(context, get_entry_data, request,
                                    client, &armor_key);
    if (retval != 0) {
        krb5_free_keyblock(context, armor_key);
        retval = EINVAL;
        goto errout;
    }

    retval = krb5_c_decrypt(context, armor_key, KRB5_KEYUSAGE_PA_OTP_REQUEST,
                            NULL, &otp_req->enc_data, &decrypted_data);
    if (retval != 0) {
        SERVER_DEBUG("Unable to decrypt encData in PA-OTP-REQUEST.");
        retval = KRB5KDC_ERR_PREAUTH_FAILED;
        goto errout;
    }

    /* Verify the server nonce (PA-OTP-ENC-REQUEST).  */
    if (decrypted_data.length != 8 + armor_key->length) {
        SERVER_DEBUG("Invalid server nonce length.");
        retval = KRB5KDC_ERR_PREAUTH_FAILED;
        goto errout;
    }
    if (krb5_us_timeofday(context, &now_sec, &now_usec)) {
        SERVER_DEBUG("Unable to get current time.");
        retval = KRB5KDC_ERR_PREAUTH_FAILED;
        goto errout;
    }
    ts_sec = ntohl(*((uint32_t *) (decrypted_data.data + armor_key->length)));
    ts_usec = ntohl(*((uint32_t *) (decrypted_data.data + armor_key->length + 4)));
    if (labs(now_sec - ts_sec) > context->clockskew
        || (labs(now_sec - ts_sec) == context->clockskew
            && ((now_sec > ts_sec && now_usec > ts_usec)
                || (now_sec < ts_sec && now_usec < ts_usec)))) {
        SERVER_DEBUG("Bad timestamp in PA-OTP-ENC-REQUEST.");
        retval = KRB5KDC_ERR_PREAUTH_FAILED; /* FIXME: KRB_APP_ERR_SKEW?  */
        goto errout;
    }
    krb5_free_data_contents(context, &decrypted_data);

    otp = strndup(otp_req->otp_value.data, otp_req->otp_value.length);
    if (otp == NULL) {
        SERVER_DEBUG("strndup failed.");
        retval = ENOMEM;
        goto errout;
    }

    retval = otp_server_create_req_ctx(otp_ctx, client, &otp_req_ctx);
    if (retval != 0) {
        goto errout;
    }

    assert(otp_req_ctx->method->ftable != NULL);
    assert(otp_req_ctx->method->ftable->server_verify != NULL);
    ret = otp_req_ctx->method->ftable->server_verify(otp_req_ctx, otp);
    free(otp);

    if (ret != 0) {
        SERVER_DEBUG("Verification for [%s] failed with %d.",
                     otp_req_ctx->token_id, ret);
        *modreq_out = NULL;
        retval = KRB5KDC_ERR_PREAUTH_FAILED;
        goto errout;
    }

    *modreq_out = (krb5_kdcpreauth_modreq) armor_key;
    enc_tkt_reply->flags |= TKT_FLG_PRE_AUTH;
    /* FIXME: Let the OTP method decide about the HW flag.  */
    enc_tkt_reply->flags |= TKT_FLG_HW_AUTH;

    SERVER_DEBUG("Verification succeeded for [%s].", otp_req_ctx->token_id);
    otp_server_free_req_ctx(&otp_req_ctx);
    return 0;

 errout:
    krb5_free_data_contents(context, &decrypted_data);
    if (armor_key != NULL) {
        krb5_free_keyblock(context, armor_key);
    }
    otp_server_free_req_ctx(&otp_req_ctx);
    return retval;
}

static krb5_error_code
otp_server_return_padata(krb5_context kcontext,
                         krb5_pa_data *padata,
                         struct _krb5_db_entry_new *client,
                         krb5_data *req_pkt,
                         krb5_kdc_req *request,
                         krb5_kdc_rep *reply,
                         struct _krb5_key_data *client_keys,
                         krb5_keyblock *encrypting_key,
                         krb5_pa_data **send_pa_out,
                         krb5_kdcpreauth_get_data_fn get_entry_data,
                         krb5_kdcpreauth_moddata moddata,
                         krb5_kdcpreauth_modreq modreq)
{
    krb5_keyblock *reply_key = NULL;
    krb5_error_code retval = -1;

    if (modreq == NULL) {
        SERVER_DEBUG("Not handled by me.");
        return 0;
    }

    reply_key = (krb5_keyblock *) modreq;
    modreq = NULL;

    krb5_free_keyblock_contents(kcontext, encrypting_key);
    retval = krb5_copy_keyblock_contents(kcontext, reply_key, encrypting_key);
    krb5_free_keyblock(kcontext, reply_key);
    if (retval != 0) {
        SERVER_DEBUG("Unable to copy reply key.");
        return retval;
    }

    return 0;
}

static krb5_preauthtype otp_server_supported_pa_types[] = {
    KRB5_PADATA_OTP_REQUEST,
    0
};

krb5_error_code
kdcpreauth_otp_initvt(krb5_context context, int maj_ver, int min_ver,
                      krb5_plugin_vtable vtable);

krb5_error_code
kdcpreauth_otp_initvt(krb5_context context, int maj_ver, int min_ver,
                      krb5_plugin_vtable vtable)
{
    krb5_kdcpreauth_vtable vt;

    if (maj_ver != 1) {
        return KRB5_PLUGIN_VER_NOTSUPP;
    }
    vt = (krb5_kdcpreauth_vtable) vtable;
    vt->name = "otp";
    vt->pa_type_list = otp_server_supported_pa_types;
    vt->init = otp_server_init;
    vt->fini = otp_server_fini;
    vt->flags = otp_server_get_flags;
    vt->edata = otp_server_get_edata;
    vt->verify = otp_server_verify;
    vt->return_padata = otp_server_return_padata;
    return 0;
}
