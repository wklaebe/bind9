/*
 * Copyright (C) 2008-2011  Red Hat, Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND Red Hat DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS.  IN NO EVENT SHALL Red Hat BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
 * OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */


#ifndef DYNAMIC_DB_H
#define DYNAMIC_DB_H

#include <isc/types.h>

#include <dns/types.h>

/*
 * TODO:
 * Reformat the prototypes.
 * Add annotated comments.
 */

isc_result_t dns_dynamic_db_load(const char *libname, const char *name,
				 isc_mem_t *mctx, const char * const *argv,
				 const dns_dyndb_arguments_t *dyndb_args);

void dns_dynamic_db_cleanup(isc_boolean_t exiting);

dns_dyndb_arguments_t *dns_dyndb_arguments_create(isc_mem_t *mctx);
void dns_dyndb_arguments_destroy(isc_mem_t *mctx, dns_dyndb_arguments_t *args);

void dns_dyndb_set_view(dns_dyndb_arguments_t *args, dns_view_t *view);
dns_view_t *dns_dyndb_get_view(dns_dyndb_arguments_t *args);
void dns_dyndb_set_zonemgr(dns_dyndb_arguments_t *args, dns_zonemgr_t *zmgr);
dns_zonemgr_t *dns_dyndb_get_zonemgr(dns_dyndb_arguments_t *args);
void dns_dyndb_set_task(dns_dyndb_arguments_t *args, isc_task_t *task);
isc_task_t *dns_dyndb_get_task(dns_dyndb_arguments_t *args);
void dns_dyndb_set_timermgr(dns_dyndb_arguments_t *args,
			    isc_timermgr_t *timermgr);
isc_timermgr_t *dns_dyndb_get_timermgr(dns_dyndb_arguments_t *args);

#endif
