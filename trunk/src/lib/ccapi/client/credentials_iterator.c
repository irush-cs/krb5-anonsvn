/* $Copyright:
 *
 * Copyright 2004-2006 by the Massachusetts Institute of Technology.
 * 
 * All rights reserved.
 * 
 * Export of this software from the United States of America may require a
 * specific license from the United States Government.  It is the
 * responsibility of any person or organization contemplating export to
 * obtain such a license before exporting.
 * 
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and distribute
 * this software and its documentation for any purpose and without fee is
 * hereby granted, provided that the above copyright notice appear in all
 * copies and that both that copyright notice and this permission notice
 * appear in supporting documentation, and that the name of M.I.T. not be
 * used in advertising or publicity pertaining to distribution of the
 * software without specific, written prior permission.  Furthermore if you
 * modify this software you must label your software as modified software
 * and not distribute it in such a fashion that it might be confused with
 * the original MIT software. M.I.T. makes no representations about the
 * suitability of this software for any purpose.  It is provided "as is"
 * without express or implied warranty.
 * 
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 * 
 * Individual source code files are copyright MIT, Cygnus Support,
 * OpenVision, Oracle, Sun Soft, FundsXpress, and others.
 * 
 * Project Athena, Athena, Athena MUSE, Discuss, Hesiod, Kerberos, Moira,
 * and Zephyr are trademarks of the Massachusetts Institute of Technology
 * (MIT).  No commercial use of these trademarks may be made without prior
 * written permission of MIT.
 * 
 * "Commercial use" means use of a name in a product or other for-profit
 * manner.  It does NOT prevent a commercial firm from referring to the MIT
 * trademarks in order to convey information (although in doing so,
 * recognition of their trademark status should be given).
 * $
 */

/* credentials_iterator.c */

#include <stdlib.h>
#include <stdio.h>
#include <CredentialsCache.h>
#include "credentials.h"
#include "credentials_iterator.h"
#include "cc_rpc.h"
#include "msg.h"
#include "msg_headers.h"


cc_int32
cc_int_credentials_iterator_new( cc_credentials_iterator_t * piter, 
                                 cc_handle ctx,
                                 cc_handle ccache,
                                 cc_handle handle )
{
    cc_int_credentials_iterator_t iter;

    if ( piter == NULL )
        return ccErrBadParam;

    iter = (cc_int_credentials_iterator_t) malloc( sizeof(cc_int_credentials_iterator_d) );
    if ( iter == NULL )
        return ccErrNoMem;

    iter->functions = (cc_credentials_iterator_f*)malloc(sizeof(cc_credentials_iterator_f));
    if ( iter->functions == NULL ) {
        free(iter);
        return ccErrNoMem;
    }

    iter->functions->release = cc_int_credentials_iterator_release;
    iter->functions->next = cc_int_credentials_iterator_next;
    iter->functions->clone = cc_int_credentials_iterator_clone;
    iter->magic = CC_CREDS_ITER_MAGIC;
    iter->ctx = ctx;
    iter->ccache = ccache;
    iter->handle = handle;

    *piter = (cc_credentials_iterator_t) iter;
    return ccNoError;
}

cc_int32
cc_int_credentials_iterator_release( cc_credentials_iterator_t iter )
{
    cc_int_credentials_iterator_t int_iter;
    cc_msg_t        		*request = NULL;
    ccmsg_creds_iterator_release_t *request_header = NULL;
    cc_msg_t        		*response = NULL;
    cc_uint32			type;
    cc_int32 			code;

    if ( iter == NULL )
        return ccErrBadParam;

    int_iter = (cc_int_credentials_iterator_t) iter;

    if ( int_iter->magic != CC_CREDS_ITER_MAGIC )
        return ccErrInvalidCredentialsIterator;

    request_header = (ccmsg_creds_iterator_release_t*)malloc(sizeof(ccmsg_creds_iterator_release_t));
    if (request_header == NULL)
        return ccErrNoMem;
    request_header->ctx = htonll(int_iter->ctx);
    request_header->ccache = htonll(int_iter->ccache);
    request_header->iterator = htonll(int_iter->handle);

    code = cci_msg_new(ccmsg_CREDS_ITERATOR_RELEASE, &request);
    if (code != ccNoError)
	goto cleanup;

    code = cci_msg_add_header(request, request_header, sizeof(ccmsg_creds_iterator_release_t));
    if (code != ccNoError)
	goto cleanup;
    request_header = NULL;

    code = cci_perform_rpc(request, &response);
    if (code != ccNoError)
	goto cleanup;

    type = htonl(response->type);
    if (type == ccmsg_NACK) {
        ccmsg_nack_t * nack_header = (ccmsg_nack_t *)response->header;
        code = htonl(nack_header->err_code);
    } else if (type == ccmsg_ACK) {
        code = ccNoError;
    } else {
        code = ccErrBadInternalMessage;
    }

  cleanup:
    if (request_header)
	free(request_header);
    if (request)
	cci_msg_destroy(request);
    if (response)
	cci_msg_destroy(response);

    free(int_iter->functions);
    free(int_iter);
    return ccNoError;
}

cc_int32
cc_int_credentials_iterator_next( cc_credentials_iterator_t iter,
                                  cc_credentials_t * credentials )
{
    cc_int_credentials_iterator_t int_iter;
    cc_msg_t        		*request = NULL;
    ccmsg_creds_iterator_next_t *request_header = NULL;
    cc_msg_t        		*response = NULL;
    cc_uint32			type;
    cc_int32 			code;

    if ( credentials == NULL )
        return ccErrBadParam;

    int_iter = (cc_int_credentials_iterator_t)iter;

    if ( int_iter->magic != CC_CREDS_ITER_MAGIC )
        return ccErrInvalidCredentialsIterator;

    request_header = (ccmsg_creds_iterator_next_t*)malloc(sizeof(ccmsg_creds_iterator_next_t));
    if (request_header == NULL)
        return ccErrNoMem;
    request_header->ctx = htonll(int_iter->ctx);
    request_header->ccache = htonll(int_iter->ccache);
    request_header->iterator = htonll(int_iter->handle);

    code = cci_msg_new(ccmsg_CREDS_ITERATOR_NEXT, &request);
    if (code != ccNoError)
	goto cleanup;

    code = cci_msg_add_header(request, request_header, sizeof(ccmsg_creds_iterator_next_t));
    if (code != ccNoError)
	goto cleanup;
    request_header = NULL;

    code = cci_perform_rpc(request, &response);
    if (code != ccNoError)
	goto cleanup;

    type = ntohl(response->type);
    if (type == ccmsg_NACK) {
        ccmsg_nack_t * nack_header = (ccmsg_nack_t *)response->header;
        code = ntohl(nack_header->err_code);
    } else if (type == ccmsg_ACK) {
        char * blob;
        ccmsg_creds_iterator_next_resp_t * response_header = (ccmsg_creds_iterator_next_resp_t*)response->header;
        code = cci_msg_retrieve_blob(response, ntohl(response_header->creds_offset), ntohl(response_header->creds_len), &blob);
        code = cc_int_credentials_new(credentials, ntohl(response_header->version),
                                  int_iter->ctx, int_iter->ccache, ntohll(response_header->creds_handle), 
                                  blob, ntohl(response_header->creds_len));
        free(blob);
    } else {
        code = ccErrBadInternalMessage;
    }

  cleanup:
    if (request_header)
	free(request_header);
    if (request)
	cci_msg_destroy(request);
    if (response)
	cci_msg_destroy(response);
    return code;
}

cc_int32
cc_int_credentials_iterator_clone( cc_credentials_iterator_t iter,
				   cc_credentials_iterator_t* new_iter)
{
    cc_int_credentials_iterator_t 	int_iter;
    cc_msg_t        			*request = NULL;
    ccmsg_creds_iterator_clone_t 	*request_header = NULL;
    cc_msg_t        			*response = NULL;
    cc_uint32				type;
    cc_int32 				code;

    if ( iter == NULL || new_iter == NULL )
        return ccErrBadParam;

    int_iter = (cc_int_credentials_iterator_t)iter;

    if ( int_iter->magic != CC_CREDS_ITER_MAGIC )
        return ccErrInvalidCCacheIterator;

    request_header = (ccmsg_creds_iterator_clone_t*)malloc(sizeof(ccmsg_creds_iterator_clone_t));
    if (request_header == NULL)
        return ccErrNoMem;
    request_header->ctx = htonll(int_iter->ctx);
    request_header->iterator = htonll(int_iter->handle);

    code = cci_msg_new(ccmsg_CREDS_ITERATOR_CLONE, &request);
    if (code != ccNoError)
	goto cleanup;

    code = cci_msg_add_header(request, request_header, sizeof(ccmsg_creds_iterator_clone_t));
    if (code != ccNoError)
	goto cleanup;
    request_header = NULL;

    code = cci_perform_rpc(request, &response);
    if (code != ccNoError)
	goto cleanup;

    type = ntohl(response->type);
    if (type == ccmsg_NACK) {
        ccmsg_nack_t * nack_header = (ccmsg_nack_t *)response->header;
        code = ntohl(nack_header->err_code);
    } else if (type == ccmsg_ACK) {
        ccmsg_creds_iterator_clone_resp_t * response_header = (ccmsg_creds_iterator_clone_resp_t*)response->header;
        code = cc_int_credentials_iterator_new(new_iter, int_iter->ctx, int_iter->ccache, ntohll(response_header->iterator));
    } else {
        code = ccErrBadInternalMessage;
    }

  cleanup:
    if (request_header)
	free(request_header);
    if (request)
	cci_msg_destroy(request);
    if (response)
	cci_msg_destroy(response);
    return code;
}
