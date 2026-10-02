# $OpenLDAP$
# This work is part of OpenLDAP Software <http://www.openldap.org/>.
#
# Copyright 2026 The OpenLDAP Foundation.
# Copyright 2026 Univention GmbH
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted only as authorized by the OpenLDAP
# Public License.
#
# A copy of this license is available in the file LICENSE in the
# top-level directory of the distribution or, alternatively, at
# <http://www.OpenLDAP.org/license.html>.

LDAP_SRC = ../../..
LDAP_BUILD = $(LDAP_SRC)
LDAP_INC = -I$(LDAP_BUILD)/include -I$(LDAP_SRC)/include -I$(LDAP_SRC)/servers/slapd
LDAP_LIB = $(LDAP_BUILD)/libraries/libldap/libldap.la \
	$(LDAP_BUILD)/libraries/liblber/liblber.la

LIBTOOL = $(LDAP_BUILD)/libtool
INSTALL = /usr/bin/install
CC = gcc
OPT = -g -O2 -Werror
DEFS = -DSLAPD_OVER_INCHAIN=SLAPD_MOD_DYNAMIC
INCS = $(LDAP_INC)
LIBS = $(LDAP_LIB)

prefix = /usr/local
exec_prefix = $(prefix)
ldap_subdir=/openldap

libdir=$(exec_prefix)/lib
libexecdir=$(exec_prefix)/libexec
moduledir = $(libexecdir)$(ldap_subdir)

OBJS = inchain.lo
MODULE = inchain.la

all: $(MODULE)

inchain.lo: inchain.c
	$(LIBTOOL) --mode=compile $(CC) $(CFLAGS) $(CPPFLAGS) $(DEFS) $(INCS) -c inchain.c

$(MODULE): $(OBJS)
	$(LIBTOOL) --mode=link $(CC) $(LDFLAGS) -rpath $(moduledir) -module -o $(MODULE) $(OBJS) $(LDFLAGS)

install: $(MODULE)
	mkdir -p $(DESTDIR)$(moduledir)
	$(LIBTOOL) --mode=install cp $(MODULE) $(DESTDIR)$(moduledir)

clean:
	rm -f *.o *.lo *.la *.so *.a
	rm -rf .libs

.PHONY: all install clean
