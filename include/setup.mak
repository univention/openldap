# $OpenLDAP: pkg/ldap/include/setup.mak,v 1.7.2.1 2003/03/03 17:10:03 kurt Exp $
#
# Copyright 1998-2003 The OpenLDAP Foundation, All Rights Reserved.
# COPYING RESTRICTIONS APPLY, see COPYRIGHT file
#

.SUFFIXES: .nt

.nt.h:
	copy $*.nt $*.h

all: setup.txt

setup.txt: lber_types.h ldap_config.h ldap_features.h portable.h setup.mak
	copy setup.mak setup.txt

lber_types.h: lber_types.nt
ldap_config.h: ldap_config.nt
ldap_features.h: ldap_features.nt
portable.h: portable.nt
