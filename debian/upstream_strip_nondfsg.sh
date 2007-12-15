#! /bin/sh
#
# Strips non-DFSG-free content from the OpenLDAP upstream tarball.  This
# script must be run from the top directory of the Debian package source
# since it needs debian/schema to know what schema to remove from upstream.

set -e

if [ "$#" -ne 1 ]; then
	echo >&2 "Usage: $0 <upstream-archive.tar.gz>"
	exit 1
fi
if [ ! -d "debian/schema" ] ; then
	echo >&2 "$0 must be run from the top directory of the Debian source"
	exit 1
fi

archive=$1


# Unpack the upstream archive to a temporary directory
tempdir=`mktemp -d`
tar -C $tempdir -xzf $archive


# Remove RFCs and drafts as they are not DFSG-free
rm -R $tempdir/openldap-*/doc/drafts
rm -R $tempdir/openldap-*/doc/rfc

# Remove schema for which we have a local stripped version.
for schema in debian/schema/*.schema debian/schema/*.ldif ; do
        file=`basename "$schema"`
        rm $tempdir/openldap-*/servers/slapd/schema/$file
done


# Recreate the archive from the data
temparchive=`mktemp $archive.XXXXXX`
tar -C $tempdir -cf - .|gzip -9 > "$temparchive"
mv $temparchive $archive

# Remove temporary files
rm -R $tempdir
