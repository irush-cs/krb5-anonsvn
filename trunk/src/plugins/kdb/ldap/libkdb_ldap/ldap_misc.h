/*
 * lib/kdb/kdb_ldap/ldap_misc.h
 *
 * Copyright (c) 2004-2005, Novell, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright notice,
 *       this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *   * The copyright holder's name is not used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _HAVE_LDAP_MISC_H
#define _HAVE_LDAP_MISC_H 1

#include "ldap_services.h"

/* misc functions */

krb5_error_code
updateAttribute (LDAP *, char *, char *, char  *);

krb5_error_code
deleteAttribute (LDAP *, char *, char *, char *);

krb5_error_code
populateServers(LDAP *, char **, char ***, char *, char **);

krb5_error_code
disjoint_members(char **, char **);

krb5_error_code
is_principal_in_realm(krb5_ldap_context *, krb5_const_principal);

krb5_error_code
checkattributevalue(LDAP *, char *, char *, char **, int *);

krb5_error_code
krb5_get_attributes_mask(krb5_context, krb5_db_entry *, int *);

krb5_error_code
krb5_get_princ_type(krb5_context, krb5_db_entry *, int *);

krb5_error_code
krb5_get_princ_count(krb5_context, krb5_db_entry *, int *);

krb5_error_code
krb5_get_secretkeys(krb5_context, krb5_db_entry *, KEY **);

krb5_error_code
krb5_get_userdn(krb5_context, krb5_db_entry *, char **);

krb5_error_code
krb5_get_containerdn(krb5_context, krb5_db_entry *, char **);

krb5_error_code
store_tl_data(krb5_tl_data *, int, void *);

krb5_error_code
decode_tl_data(krb5_tl_data *, int, void **);

krb5_error_code
is_principal_in_realm(krb5_ldap_context *, krb5_const_principal);

krb5_error_code
krb5_get_subtree_info(krb5_ldap_context *, char **, unsigned int *);

krb5_error_code
krb5_ldap_read_server_params(krb5_context , char *, int);

krb5_error_code
krb5_ldap_free_server_params(krb5_ldap_context *);

krb5_error_code
copy_arrays(char **, char ***, int);

krb5_error_code
krb5_ldap_list(krb5_context, char ***, char *, char *);

krb5_error_code 
krb5_ldap_get_value(LDAP *, LDAPMessage *, char *, int *);

krb5_error_code 
krb5_ldap_get_string(LDAP *, LDAPMessage *, char *, char **, krb5_boolean *);

krb5_error_code 
krb5_ldap_get_time(LDAP *, LDAPMessage *, char *, krb5_timestamp *, krb5_boolean *);

krb5_error_code
krb5_add_member(LDAPMod ***, int *);

krb5_error_code
krb5_add_str_mem_ldap_mod(LDAPMod  ***, char *, int, char **);

krb5_error_code
krb5_add_ber_mem_ldap_mod(LDAPMod  ***, char *, int, struct berval **);

krb5_error_code
krb5_add_int_arr_mem_ldap_mod(LDAPMod  ***, char *, int, int *);

krb5_error_code
krb5_add_int_mem_ldap_mod(LDAPMod  ***, char *, int , int);

krb5_error_code
krb5_ldap_free_mod_array(LDAPMod **);

#endif