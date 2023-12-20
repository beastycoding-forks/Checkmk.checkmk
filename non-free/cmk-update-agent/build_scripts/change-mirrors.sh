#!/bin/bash

set -e -o pipefail

# https://vault.centos.org/
echo "Changing Centos Mirrors to:"

# this mirror should do its job
if [ "$ARCHITECTURE" == "amd64" ]; then
    export ARCHITECTURE="x86_64"
fi

cat <<EOF >>/etc/yum.repos.d/base.repo
[base1]
name=Centos 6 mirror
baseurl=http://archive.kernel.org/centos-vault/6.10/os/$ARCHITECTURE/
priority=0

[base2]
name=Centos 6 mirror alternative
baseurl=http://linuxsoft.cern.ch/centos-vault/6.10/os/$ARCHITECTURE/
priority=1

[base3]
name=Centos 6 mirror alternative II
baseurl=http://mirror.nsc.liu.se/centos-store/6.10/os/$ARCHITECTURE/
priority=2

# no http connections allowed to Nexus :(
EOF

cat /etc/yum.repos.d/base.repo
