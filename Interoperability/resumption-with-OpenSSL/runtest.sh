#!/bin/bash
# vim: dict+=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/gnutls/Interoperability/resumption-with-OpenSSL
#   Description: What the test does
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
        rlRun "TmpDir=\$(mktemp -d)" 0 "Creating tmp directory"
        rlRun "pushd $TmpDir"
        rlRun "openssl req -x509 -newkey rsa -keyout localhost.key -out localhost.crt -nodes -batch -subj /CN=localhost"

        if ! rlIsRHEL "<8"; then
            fips_status="$(fips-mode-setup --check)"

            # Switch to LEGACY only in non-FIPS mode.
            if [[ "$fips_status" =~ "disabled" ]]; then
                # TLS1.2 is a minimum in DEFAULT policy with crypto-policies.
                # To allow TLS1.1 LEGACY policy must be set.
                policy_old=$(update-crypto-policies --show)
                rlRun "update-crypto-policies --set LEGACY"
            fi
        fi
    rlPhaseEnd

    rlPhaseStartTest "openssl server"

        # In TLS 1.3 the session tickets are sent after the handshake was
        # performed, so we would need to read some data from the socket.
        # As there already exists
        # /CoreOS/openssl/Interoperability/tls-1-3-interoperability-gnutls-openssl
        # won't be updating this test case to duplicate it here.
        # Limiting server not to use TLS1.3.
        if ! rlIsRHEL "<8"; then
            rlRun "openssl s_server -www -key localhost.key -cert localhost.crt -no_tls1_3 >server.log 2>server.err &"
        else
            rlRun "openssl s_server -www -key localhost.key -cert localhost.crt >server.log 2>server.err &"
        fi
        openssl_pid=$!
        rlRun "rlWaitForSocket -p $openssl_pid 4433"
        for sett in NORMAL "NORMAL:-VERS-ALL:+VERS-TLS1.1" "NORMAL:-VERS-ALL:+VERS-TLS1.2"; do
            [[ "$sett" =~ "-VERS-ALL:+VERS-TLS1.1" ]] && continue
            # On RHEL 8.3, --waitresumption option was added to gnutls-cli (#1677754)
            if rlIsRHEL '<8.3'; then
                rlRun -s "gnutls-cli --priority '$sett' --resume --x509cafile localhost.crt --port 4433 localhost </dev/null"
            else
                rlRun -s "gnutls-cli --priority '$sett' --resume --waitresumption --x509cafile localhost.crt --port 4433 localhost </dev/null"
            fi
            rlAssertGrep "This is a resumed session" $rlRun_LOG
            rlAssertNotGrep "failure" $rlRun_LOG -i

        done
        rlRun "kill $openssl_pid"
        rlRun "rlWait -s 9 $openssl_pid" 143

        if ! rlGetPhaseState; then
            rlRun "cat server.log"
            rlRun "cat server.err"
        fi
    rlPhaseEnd

    rlPhaseStartTest "gnutls server"
        rlRun "gnutls-serv --priority NORMAL:+VERS-TLS1.2 --x509keyfile localhost.key --x509certfile localhost.crt --http --port 4433 >server.log 2>server.err &"
        gnutls_pid=$!
        rlRun "rlWaitForSocket -p $gnutls_pid 4433"

        # In TLS 1.3 the session tickets are sent after the handshake was
        # performed, so we would need to read some data from the socket.
        # As there already exists
        # /CoreOS/openssl/Interoperability/tls-1-3-interoperability-gnutls-openssl
        # won't be updating this test case to duplicate it here
        PROTOCOLS=("" "-tls1_1" "-tls1_2")
        if rlIsRHEL "6" && rlIsRHEL "<6.5"; then
            PROTOCOLS=("")
        elif rlIsFedora && ! rlIsFedora "<33"; then
            PROTOCOLS=("-tls1_2")  # We're disabling TLSv1.1 since Fedora 33
        elif rlIsRHEL "8"; then
            # In FIPS mode on RHEL8, TLS<1.2 is disabled.
            if [[ "$fips_status" =~ "enabled" ]]; then
                PROTOCOLS=("-tls1_2")
            else
                PROTOCOLS=("-tls1_1" "-tls1_2")
            fi
        elif ! rlIsRHEL "<9"; then
            PROTOCOLS=("-tls1_2")
        fi
        for sett in "${PROTOCOLS[@]}"; do
            rlRun -s "openssl s_client -connect localhost:4433 -no_ticket -CAfile localhost.crt $sett -sess_out sess.pem </dev/null"
            if rlIsRHEL '<8'; then
                rlAssertGrep "New, TLSv1/SSLv3" $rlRun_LOG
                rlAssertNotGrep "Reused, TLSv1/SSLv3" $rlRun_LOG
            else
                rlAssertGrep "New, TLSv1." $rlRun_LOG
                rlAssertNotGrep "Reused, TLSv1." $rlRun_LOG
            fi
            rlAssertGrep "Verify return code: 0 (ok)" $rlRun_LOG
            rlRun -s "openssl s_client -connect localhost:4433 -no_ticket -CAfile localhost.crt $sett -sess_in sess.pem </dev/null"
            if rlIsRHEL '<8'; then
                rlAssertGrep "Reused, TLSv1/SSLv3" $rlRun_LOG
                rlAssertNotGrep "New, TLSv1/SSLv3" $rlRun_LOG
            else
                rlAssertGrep "Reused, TLSv1." $rlRun_LOG
                rlAssertNotGrep "New, TLSv1." $rlRun_LOG
            fi
            rlAssertGrep "Verify return code: 0 (ok)" $rlRun_LOG
        done
        rlRun "kill $gnutls_pid" 0,1
        rlRun "rlWait -s 9 $gnutls_pid" 143,1
        if ! rlGetPhaseState; then
            rlRun "cat server.log"
            rlRun "cat server.err"
        fi
    rlPhaseEnd

    rlPhaseStartCleanup
        [ -n "$policy_old" ] && rlRun "update-crypto-policies --set $policy_old"
        rlRun "popd"
        rlRun "rm -r $TmpDir" 0 "Removing tmp directory"
    rlPhaseEnd
rlJournalPrintText
rlJournalEnd
