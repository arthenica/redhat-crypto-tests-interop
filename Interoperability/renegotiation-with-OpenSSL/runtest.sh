#!/bin/bash
# vim: dict+=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/gnutls/Interoperability/renegotiation-with-OpenSSL
#   Description: Test if renegotiation with OpenSSL works
#   Author: Hubert Kario <hkario@redhat.com>
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Copyright (c) 2016 Red Hat, Inc.
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
PACKAGES="gnutls openssl"

rlJournalStart
    rlPhaseStartSetup
        rlAssertRpm --all
        rlRun "rlImport fips"
        fipsIsEnabled
        fips=$?
        if [[ $fips -eq 2 ]]; then
            rlDie "FIPS mode misconfigured"
            exit 1
        fi
        rlRun "TmpDir=\$(mktemp -d)" 0 "Creating tmp directory"
        rlRun "pushd $TmpDir"
        rlRun "openssl req -x509 -newkey rsa -keyout localhost.key -out localhost.crt -nodes -batch -subj /CN=localhost"
        if ! rlIsRHEL "<8"; then
            openssl_server_opts="-no_tls1_3"
            policy_backup="$(update-crypto-policies --show)"
            if [[ $fips -eq 1 ]]; then
                rlRun "update-crypto-policies --set LEGACY" 0
            fi
        fi
    rlPhaseEnd

    rlPhaseStartTest "openssl server"
        if rlIsRHEL && ! rlIsRHEL '<9' || rlIsFedora && ! rlIsFedora '<36'; then
            # openssl 3.0 change, client renegotiation is disabled by default
            # https://github.com/openssl/openssl/commit/55373bfd419ca010a15aac18c88c94827e2f3a92
            openssl_server_opts+=" -client_renegotiation"
        fi
        rlRun "openssl s_server $openssl_server_opts -www -key localhost.key -cert localhost.crt >server.log 2>server.err &"
        openssl_pid=$!
        rlRun "rlWaitForSocket -p $openssl_pid 4433"
        for sett in NORMAL "NORMAL:+VERS-TLS1.2" "NORMAL:-VERS-ALL:+VERS-TLS1.0:+VERS-TLS1.1"; do

            # In RHEL-8 & FIPS, only TLS <1.2 is not allowed.
            # same for RHEL-9
            if ( ! rlIsRHEL "<8" && [[ $fips -eq 0 ]] ) || ! rlIsRHEL '<9'; then
                [[ "$sett" =~ "-VERS-ALL:+VERS-TLS1.0:+VERS-TLS1.1" ]] && continue
            fi
            rlRun -s "gnutls-cli --priority '$sett' --rehandshake --x509cafile localhost.crt --port 4433 localhost </dev/null"
            rlAssertGrep "ReHandshake was completed" $rlRun_LOG
            rlAssertNotGrep "failure" $rlRun_LOG -i
        done
        rlRun "kill $openssl_pid" 0,1
        rlRun "rlWait $openssl_pid" 143
        rlGetPhaseState || rlRun 'cat server.log'
        rlGetPhaseState || rlRun 'cat server.err'
    rlPhaseEnd

    rlPhaseStartTest "gnutls server"
        rlRun "gnutls-serv --priority NORMAL:-VERS-ALL:+VERS-TLS1.1:+VERS-TLS1.2 --x509keyfile localhost.key --x509certfile localhost.crt --http --port 4433 >server.log 2>server.err &"
        gnutls_pid=$!
        rlRun "rlWaitForSocket -p $gnutls_pid 4433"
        PROTOCOLS=("" "-tls1_1" "-tls1_2")
        if rlIsRHEL 6 && rlIsRHEL '<6.5'; then
            PROTOCOLS=("")
        fi
        for sett in "${PROTOCOLS[@]}"; do

            if ( ! rlIsRHEL "<8" && [[ $fips -eq 0 ]] ) || ! rlIsRHEL '<9'; then
                [[ "$sett" =~ "-tls1_1" ]] && continue
            fi
            rlRun -s "(sleep 1; echo R; sleep 1; echo Q) | openssl s_client -connect localhost:4433 -CAfile localhost.crt $sett"
            rlAssertGrep "RENEGOTIATING" $rlRun_LOG
            rlRun "grep -A 10 RENEGOTIATING $rlRun_LOG | grep 'verify return:1'"
        done
        rlRun "kill $gnutls_pid" 0,1
        rlRun "rlWait $gnutls_pid" 1,143
        rlGetPhaseState || rlRun 'cat server.log'
        rlGetPhaseState || rlRun 'cat server.err'
    rlPhaseEnd

    rlPhaseStartCleanup
        if ! rlIsRHEL "<8" && [[ $fips -eq 1 ]]; then
            rlRun "update-crypto-policies --set $policy_backup" 0
        fi
        rlRun "popd"
        rlRun "rm -r $TmpDir" 0 "Removing tmp directory"
    rlPhaseEnd
rlJournalPrintText
rlJournalEnd
