#!/bin/bash
# vim: dict+=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/gnutls/Interoperability/tls-1-3-interoperability-gnutls-nss-2way
#   Description: Test TLS 1.3 interoperability between NSS and OpenSSL
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

PACKAGE='openssl'
PACKAGES='openssl nss'

TWAY=2

SLICE_TOTAL=${SLICE_TOTAL:-1}
SLICE_ID=${SLICE_ID:-0}

rlJournalStart
    rlPhaseStartSetup
        rlAssertRpm --all

        rlRun 'rlImport fips'
        if ! fipsIsEnabled; then
            TWAY_CSV=${TWAY}way.csv
        else
            TWAY_CSV=${TWAY}way.fips.csv
        fi

        rlRun 'rlImport tls-1-3-interoperability-gnutls-nss'
        rlRun "TmpDir=\$(mktemp -d)" 0 'Creating tmp directory'
        TEST_DIR=$(pwd)
        rlRun "pushd $TmpDir"

        tls13interop_gnutls_nss_setup

        CONF_ITERATED_COUNTER=0
        CONF_ITERATED_TOTAL=$(grep '^# Number of configurations' $TEST_DIR/$TWAY_CSV | \
                              sed -E 's/# Number of configurations: ([0-9]+)/\1/')
        [[ "$CONF_ITERATED_TOTAL" -gt 0 ]] || \
            rlDie 'Configuration number detection problem'
        rlLog "Total $CONF_ITERATED_TOTAL configurations, slice $SLICE_ID of $SLICE_TOTAL"
        if (( SLICE_ID >= SLICE_TOTAL )); then
            rlFail "More slices than declared ($SLICE_ID >= $SLICE_TOTAL)"
        fi
    rlPhaseEnd

    CONF_TESTED_COUNTER=0
    while read LINE; do
        if [[ $LINE = \#* ]]; then
            continue
        fi
        if [[ $LINE = 'cert,c_name,c_sig,g_name,HRR,resume' ]]; then
            continue
        fi
        IFS=',' read -r cert c_name c_sig g_name g_type sess_type \
            <<<"$LINE"
        [[ $g_type == 'true' ]] && g_type=' HRR' || g_type=''
        [[ $sess_type == 'true' ]] && sess_type=' resume' || sess_type=''

        if (( CONF_ITERATED_COUNTER % SLICE_TOTAL == SLICE_ID )); then
            (( CONF_TESTED_COUNTER+=1 ))

            tls13interop_gnutls_nss_test \
                "$cert" "$c_name" "$c_sig" "$g_name" \
                "$g_type" "$sess_type" ''

            tls13interop_gnutls_nss_test \
                "$cert" "$c_name" "$c_sig" "$g_name" \
                "$g_type" "$sess_type" ' key update'
        fi

        (( CONF_ITERATED_COUNTER += 1 ))
    done < $TEST_DIR/$TWAY_CSV

    rlPhaseStartTest "Check that we did everything we expected"
        rlAssertEquals "We have iterated over $CONF_ITERATED_COUNTER configurations, "`
                      `"should be $CONF_ITERATED_TOTAL" \
                       "$CONF_ITERATED_COUNTER" "$CONF_ITERATED_TOTAL"
        CONF_TESTED_TOTAL=$(( CONF_ITERATED_TOTAL / SLICE_TOTAL ))
        if (( CONF_ITERATED_TOTAL % SLICE_TOTAL != 0
                && SLICE_ID < CONF_ITERATED_TOTAL % SLICE_TOTAL )); then
            (( CONF_TESTED_TOTAL += 1 ))
        fi
        rlAssertEquals "We have actually tested $CONF_TESTED_COUNTER configurations, "`
                      `"should be $CONF_TESTED_TOTAL" \
                       "$CONF_TESTED_COUNTER" "$CONF_TESTED_TOTAL"
    rlPhaseEnd

    rlPhaseStartCleanup
        tls13interop_gnutls_nss_cleanup
        rlRun 'popd'
        rlRun "rm -r $TmpDir" 0 'Removing tmp directory'
    rlPhaseEnd
rlJournalPrintText
rlJournalEnd
