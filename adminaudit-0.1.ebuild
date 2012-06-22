# Copyright 1999-2012 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2
# $Header: $

EAPI=4

inherit eutils
DESCRIPTION="MySQL Audit plugin to track administrative (humans-only) actions"

HOMEPAGE="http://github.com/maxximino/adminaudit"

SRC_URI="http://github.com/maxximino/adminaudit/tarball/v${PV} -> ${PN}-git-${PV}.tgz"

LICENSE="LGPL"

SLOT="0"

KEYWORDS="~x86 ~amd64"

IUSE=""

DEPEND=">=virtual/mysql-5.5"
RDEPEND="${DEPEND}"
S="${WORKDIR}"
src_prepare(){
	cd ${WORKDIR}/maxximino-${PN}-*
    S=$(pwd)
}
src_compile() {
	emake || die
}

src_install() {
	emake DESTPREFIX="${D}" install || die
	MYCNF=/etc/mysql/my.cnf
# PROBLEM: starting mysqld, even with --verbose --help, disturbs the sandbox.
# TODO: Find a better alternative than hardcoding the most common path.
#	for cnf in $(mysqld --verbose --help 2>/dev/null|grep -a1 'Default options are read'); do
#		if [ -f $cnf ]; then 
#			MYCNF=$cnf; 
#			break; 
#		fi; 
#	done
	grep adminaudit $MYCNF >/dev/null;
	if [ "$?" == "1" ]; then
		mkdir -p $(dirname $D/$MYCNF)
		cat $MYCNF ${S}/example.conf >$D/$MYCNF
	fi
}
