#!/bin/bash
# vim: dict+=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/openssl/Interoperability/tls-1-3-interoperability-gnutls-openssl-3way
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
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# Include Beaker environment
. /usr/share/beakerlib/beakerlib.sh || exit 1

PACKAGE="openssl"
PACKAGES="openssl gnutls"

TWAY=3way

rlJournalStart
    rlPhaseStartSetup
        rlAssertRpm --all

        rlRun "rlImport fips"
        if ( ! rlIsRHEL '<9' ) && ( ! rlIsFedora); then
            TWAY="${TWAY}-9.0"
        fi
        if ! fipsIsEnabled; then
            TWAY_CSV=${TWAY}.csv
        else
            TWAY_CSV=${TWAY}.fips.csv
        fi

        rlRun "rlImport tls-1-3-interoperability-gnutls-openssl"
        rlRun "TmpDir=\$(mktemp -d)" 0 "Creating tmp directory"
        TEST_DIR=$(pwd)
        rlRun "pushd $TmpDir"

        tls13interop_gnutls_openssl_setup

        CONF_COUNTER=0
        CONF_TOTAL=$(grep '^# Number of configurations' $TEST_DIR/$TWAY_CSV | \
                     sed -E 's/# Number of configurations: ([0-9]+)/\1/')
        [[ "$CONF_TOTAL" -gt 0 ]] || \
            rlDie "Configuration number detection problem"
        rlLog "Gotta test $CONF_TOTAL configuration"
    rlPhaseEnd

    while read LINE; do
        if [[ $LINE = \#* ]]; then
            continue
        fi
        if [[ $LINE = 'cert,c_name,c_sig,g_name,HRR,resume,k_update' ]]; then
            continue
        fi
        IFS=',' read -r cert c_name c_sig g_name g_type sess_type k_update \
            <<<"$LINE"
        [[ $g_type == 'true' ]] && g_type=' HRR' || g_type=''
        [[ $sess_type == 'true' ]] && sess_type=' resume' || sess_type=''
        [[ $k_update == 'true' ]] && k_update=' key update' || k_update=''
        tls13interop_gnutls_openssl_test \
            "$cert" "$c_name" "$c_sig" "$g_name" \
            "$g_type" "$sess_type" "$k_update"
        let CONF_COUNTER+=1
    done < $TEST_DIR/$TWAY_CSV

    rlPhaseStartTest "Check that we have tested $CONF_TOTAL configurations"
        rlAssertEquals "We have tested $CONF_COUNTER configurations, \
                        should be $CONF_TOTAL" \
                       "$CONF_COUNTER" "$CONF_TOTAL"
    rlPhaseEnd

    rlPhaseStartCleanup
        rlRun "popd"
        rlRun "rm -r $TmpDir" 0 "Removing tmp directory"
    rlPhaseEnd
rlJournalPrintText
rlJournalEnd
