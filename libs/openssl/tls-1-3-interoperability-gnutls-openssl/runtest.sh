#!/bin/bash
# vim: dict+=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/openssl/Interoperability/tls-1-3-interoperability-gnutls-openssl
#   Description: Test TLS 1.3 interoperability between GnuTLS and OpenSSL
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

# Include Beaker environment
. /usr/share/beakerlib/beakerlib.sh || exit 1

PACKAGE="openssl"
PACKAGES="openssl gnutls"

rlJournalStart
    rlPhaseStartSetup
        rlAssertRpm --all
        rlRun "rlImport distribution/fips"
        rlRun ". lib.sh"
        rlRun "TmpDir=\$(mktemp -d)" 0 "Creating tmp directory"
        rlRun "pushd $TmpDir"

        tls13interop_gnutls_openssl_setup
    rlPhaseEnd

    # manually defined 1-way coverage
    tls13interop_gnutls_openssl_test \
        rsa        TLS_AES_128_GCM_SHA256       SHA256  default '' '' ''

    tls13interop_gnutls_openssl_test \
        rsa-pss    TLS_AES_256_GCM_SHA384       SHA384  P-256 \
        ' HRR' ' resume' ' key update'

    tls13interop_gnutls_openssl_test \
        ecdsa-p256 TLS_AES_128_CCM_SHA256       default P-384   '' '' ''

    tls13interop_gnutls_openssl_test \
        ecdsa-p384 TLS_AES_128_CCM_8_SHA256     default P-521 \
        ' HRR' ' resume' ' key update'

    tls13interop_gnutls_openssl_test \
        ecdsa-p521 TLS_AES_128_GCM_SHA256       default default  '' '' ''

    if ! fipsIsEnabled; then
        tls13interop_gnutls_openssl_test \
            rsa TLS_CHACHA20_POLY1305_SHA256    SHA512  X25519 \
            ' HRR' ' resume' ' key update'

        if ( ! rlIsRHEL '<9' ) && ! rlIsFedora; then
            # GnuTLS supports ed25519 and ed448 since RHEL-9
            tls13interop_gnutls_openssl_test \
                ed25519 TLS_AES_128_GCM_SHA256 default X25519 \
                ' HRR' ' resume' ' key update'

            # note that Ed448 is broken in RHEL-9 beta: RHBZ#1983676
            tls13interop_gnutls_openssl_test \
                ed448 TLS_CHACHA20_POLY1305_SHA256 default X448 '' '' ''
        fi
    else
        tls13interop_gnutls_openssl_test \
            rsa TLS_AES_128_GCM_SHA256          SHA512  P-256 \
            ' HRR' ' resume' ' key update'
    fi

    if ( ! rlIsRHEL '<9' ) && ! rlIsFedora; then
        tls13interop_gnutls_openssl_test \
            rsa TLS_AES_128_GCM_SHA256 SHA256 FFDHE2048 '' '' ''

        tls13interop_gnutls_openssl_test \
            rsa TLS_AES_128_GCM_SHA256 SHA512 FFDHE8192 \
            ' HRR' ' resume' ' key update'
    fi

    rlPhaseStartCleanup
        rlRun "popd"
        rlRun "rm -r $TmpDir" 0 "Removing tmp directory"
    rlPhaseEnd
rlJournalPrintText
rlJournalEnd
