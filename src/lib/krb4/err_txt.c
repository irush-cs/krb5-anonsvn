/*
 * lib/krb4/err_txt.c
 *
 * Copyright 1988, 2002 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 * 
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 */

#include "krb.h"
#include "krb4int.h"

/*
 * This is gross.  We want krb_err_txt to match the contents of the
 * com_err error table, but the text is static in krb_err.c.  To avoid
 * multiple registrations of the error table, we also want to override
 * initialize_krb_error_table() in case someone decides to call it.
 */
#undef initialize_krb_error_table
#define initialize_krb_error_table	krb4int_init_krb_err_tbl
void krb4int_init_krb_err_tbl(void);
#include "krb_err.c"
#undef initialize_krb_error_table

void initialize_krb_error_table(void);

/* YUCK -- depends on naming of the static table. */
const char * const * const krb_err_txt = text;

static int inited = 0;

void
krb4int_et_init(void)
{
    if (inited)
	return;
    add_error_table(&et_krb_error_table);
    inited = 1;\
}

void
initialize_krb_error_table(void)
{
    krb4int_et_init();
}

void
krb4int_et_fini(void)
{
    if (inited)
	remove_error_table(&et_krb_error_table);
}

const char * KRB5_CALLCONV
krb_get_err_text(code)
    int code;
{
    krb4int_et_init();
    /*
     * Shift krb error code into com_err number space.
     */
    if (code >= 0 && code < MAX_KRB_ERRORS)
	return error_message(ERROR_TABLE_BASE_krb + code);
    else
	return "Invalid Kerberos error code";
}
