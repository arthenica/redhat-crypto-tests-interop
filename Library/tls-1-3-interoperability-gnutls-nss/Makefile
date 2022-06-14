# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Makefile of /CoreOS/gnutls/Interoperability/tls-1-3-interoperability-gnutls-nss
#   Description: Test TLS 1.3 interoperability between NSS and GnuTLS
#   Author: Hubert Kario <hkario@redhat.com>
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Copyright (c) 2018 Red Hat, Inc.
#
#   This copyrighted material is made available to anyone wishing
#   to use, modify, copy, or redistribute it subject to the terms
#   and conditions of the GNU General Public License version 2.
#
#   This program is distributed in the hope that it will be
#   useful, but WITHOUT ANY WARRANTY; without even the implied
#   warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
#   PURPOSE. See the GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public
#   License along with this program; if not, write to the Free
#   Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
#   Boston, MA 02110-1301, USA.
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

export TEST=/CoreOS/gnutls/Library/tls-1-3-interoperability-gnutls-nss
export TESTVERSION=1.0

BUILT_FILES=

FILES=$(METADATA) runtest.sh lib.sh Makefile PURPOSE gnutls-client.expect nss-client.expect nss-server.expect gnutls-resume.expect

.PHONY: all install download clean

run: $(FILES) build
	./runtest.sh

build: $(BUILT_FILES)
	test -x runtest.sh || chmod a+x runtest.sh

clean:
	rm -f *~ $(BUILT_FILES)


include /usr/share/rhts/lib/rhts-make.include

# Requires is broken for libraries: http://wiki.test.redhat.com/BaseOs/BeakerLibraries/DevelDoc
$(METADATA): Makefile
	@echo "Owner:           Hubert Kario <hkario@redhat.com>" > $(METADATA)
	@echo "Name:            $(TEST)" >> $(METADATA)
	@echo "TestVersion:     $(TESTVERSION)" >> $(METADATA)
	@echo "Path:            $(TEST_DIR)" >> $(METADATA)
	@echo "Description:     Test TLS 1.3 interoperability between NSS and GnuTLS" >> $(METADATA)
	@echo "Type:            Interoperability" >> $(METADATA)
	@echo "TestTime:        12h" >> $(METADATA)
	@echo "RunFor:          gnutls nss" >> $(METADATA)
	@echo "Provides:        library(gnutls/tls-1-3-interoperability-gnutls-nss)" >> $(METADATA)
	@echo "Priority:        Normal" >> $(METADATA)
	@echo "License:         GPLv2" >> $(METADATA)
	@echo "Confidential:    no" >> $(METADATA)
	@echo "Destructive:     no" >> $(METADATA)
	@echo "Releases:        -RHEL4 -RHEL6 -RHEL7 -RHELClient5 -RHELServer5" >> $(METADATA)

	rhts-lint $(METADATA)
