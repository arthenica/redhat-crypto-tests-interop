#!/bin/bash
# vim: dict+=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/gnutls/Interoperability/certificates-with-OpenSSL
#   Description: Verify interoperability of certificates for GnuTLS with OpenSSL
#   Author: Tomáš Mráz <tmraz@redhat.com>
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Copyright (c) 2019 Red Hat, Inc.
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

# Include Beaker environment
. /usr/share/beakerlib/beakerlib.sh || exit 1

PACKAGE="gnutls"
PACKAGES="openssl gnutls"

rlJournalStart
    rlPhaseStartSetup
        rlAssertRpm --all
        rlRun "rlImport certgen"
        rlRun "rlImport fips"
        rlRun "TmpDir=\$(mktemp -d)" 0 "Creating tmp directory"
        rlRun "cp server.tpl ca.tpl $TmpDir"
        rlRun "pushd $TmpDir"
        fipsIsEnabled
        fips=$?
        if [[ $fips -eq 0 ]]; then
            rlLogInfo "FIPS mode enabled"
        elif [[ $fips -eq 1 ]]; then
            rlLogInfo "FIPS mode disabled"
        else
            rlDie "FIPS mode misconfigured"
            exit 1
        fi

        rlLogInfo "Loading configuration..."

        i=0

        # We need to test SHA2-224, 256, 384, 512, SHA3-224, 256, 384, 512

        # Test description
        declare -a C_TEST
        # The hash identifier
        declare -a C_HASH
        # The type identifier
        declare -a C_TYPE

        for hash in SHA224 SHA256 SHA384 SHA512 ; do
           for type in rsa ecdsa ; do
              C_TEST[$i]="$type with $hash"
              C_HASH[$i]="$hash"
              C_TYPE[$i]="$type"
              i=$(($i+1))
           done
        done
        for hash in SHA3-224 SHA3-256 SHA3-384 SHA3-512 ; do
            if [[ $fips -eq 0 ]]; then  # FIPS mode enabled
                # bz1987974: SHA3-224 is not enabled in FIPS because... it's not
                [[ $hash == SHA3-224 ]] && continue
            fi
            # No SHA3 support for ECDSA yet
            for type in rsa; do
               C_TEST[$i]="$type with $hash"
               C_HASH[$i]="$hash"
               C_TYPE[$i]="$type"
               i=$(($i+1))
            done
        done
        rlLogInfo "Configuration loaded"
    rlPhaseEnd

    for j in ${!C_TEST[@]}; do
        rlPhaseStartTest "OpenSSL generation GnuTLS verification ${C_TEST[$j]}"
            rlRun "x509KeyGen -t ${C_TYPE[$j]} ca"
            rlRun "x509KeyGen -t ${C_TYPE[$j]} server"
            rlRun "x509SelfSign --md ${C_HASH[$j]} ca"
            rlRun "x509CertSign --md ${C_HASH[$j]} --CA ca --DN 'CN=server' server"
            rlRun "x509DumpCert ca" 0 "Root CA"
            rlRun "x509DumpCert server" 0 "Server certificate"
            rlRun "certtool --verify --infile $(x509Cert server) --load-ca-certificate $(x509Cert ca)"
        rlPhaseEnd
        rlPhaseStartTest "GnuTLS generation OpenSSL verification ${C_TEST[$j]}"
            t="${C_TYPE[$j]}"
            if [[ "$t" = ecdsa ]] ; then
                t="ecc"
            fi
            rlRun "certtool --generate-privkey --outfile ca-key.pem --$t"
            rlRun "certtool --generate-privkey --outfile server-key.pem --$t"
            rlRun "certtool --generate-self-signed --template ca.tpl --load-privkey ca-key.pem --outfile ca-cert.pem --hash ${C_HASH[$j]}"
            rlRun "certtool --generate-certificate --template server.tpl --load-privkey server-key.pem --outfile server-cert.pem --load-ca-certificate ca-cert.pem --load-ca-privkey ca-key.pem --hash ${C_HASH[$j]}"
            rlRun "openssl x509 -in ca-cert.pem -noout -text" 0 "Root CA"
            rlRun "openssl x509 -in server-cert.pem -noout -text" 0 "Server certificate"
            rlRun "openssl verify -CAfile ca-cert.pem server-cert.pem"
        rlPhaseEnd
    done


    rlPhaseStartCleanup
        rlRun "popd"
        rlRun "rm -r $TmpDir" 0 "Removing tmp directory"
    rlPhaseEnd
rlJournalPrintText
rlJournalEnd
