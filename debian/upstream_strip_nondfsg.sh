#! /bin/sh -e

if [ "$#" -ne 1 ]; then
	echo >&2 "Usage: $0 <upstream-archive.tar.gz>"
	exit 1
fi

archive=$1


# Unpack the upstream archive to a temporary directory
tempdir=`mktemp -d`
tar -C $tempdir -xzf $archive


# Remove RFCs as they are not DFSG-free
rm -R $tempdir/openldap-*/doc/rfc


# Recreate the archive from the data
temparchive=`mktemp $archive.XXXXXX`
tar -C $tempdir -cf - .|gzip -9 > "$temparchive"
mv $temparchive $archive

# Remove temporary files
rm -R $tempdir
