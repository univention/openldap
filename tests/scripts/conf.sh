#! /bin/sh
# $OpenLDAP: pkg/ldap/tests/scripts/conf.sh,v 1.5.2.2 2002/06/20 20:12:35 kurt Exp $
if [ x"$MONITORDB" = x"yes" ] ; then
	MON=monitor
else
	MON=nomonitor
fi
sed -e "s/@BACKEND@/$BACKEND/" -e "s/^#$BACKEND#//"  -e "s/^#$MON#//"
