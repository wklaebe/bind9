#!/bin/sh
#
# Copyright (C) 2011  Internet Systems Consortium, Inc. ("ISC")
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
# REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
# LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
# OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.

# $Id: prereq.sh,v 1.3 2011-10-28 12:20:31 tbox Exp $

if $PERL -e 'use Net::DNS;' 2>/dev/null
then
	vers=`perl -MNet::DNS -e 'print "$Net::DNS::VERSION\n"'|awk -F. '{ print $1 }'`
	
	if [ $vers -ge 66 ]
	then
    		:
	else
    		echo "I:This test requires the version 0.66 or later of the Net::DNS library." >&2
    		exit 255
	fi
else
    echo "I:This test requires the Net::DNS library." >&2
    exit 255
fi