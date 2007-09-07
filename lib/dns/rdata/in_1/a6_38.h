/*
 * Copyright (C) 1999, 2000  Internet Software Consortium.
 * 
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM DISCLAIMS
 * ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL INTERNET SOFTWARE
 * CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
 * ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 */

#ifndef IN_1_A6_38_H
#define IN_1_A6_38_H 1

/* $Id: a6_38.h,v 1.14 2000/06/16 21:41:28 gson Exp $ */

/* draft-ietf-ipngwg-dns-lookups-03.txt */

typedef struct dns_rdata_in_a6 {
        dns_rdatacommon_t	common;
	isc_mem_t		*mctx;
	dns_name_t		prefix;
	isc_uint32_t		prefixlen;
	struct in6_addr		in6_addr;
} dns_rdata_in_a6_t;

#endif /* IN_1_A6_38_H */
