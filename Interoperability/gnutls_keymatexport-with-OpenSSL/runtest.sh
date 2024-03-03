#!/bin/bash
# vim: dict+=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/gnutls/Interoperability/keymatexport-with-OpenSSL
#   Description: Verify interoperability of GnuTLS keymatexport with OpenSSL
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
        rlRun "cp gnutls-client.expect openssl-client.expect openssl-server.expect $TmpDir"
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

        rlRun "x509KeyGen ca"
        rlRun "x509KeyGen rsa-ca"
        rlRun "x509KeyGen rsa-server"
        rlRun "x509SelfSign ca"
        rlRun "x509CertSign --CA ca -t ca --DN 'CN=RSA CA' rsa-ca"
        rlRun "x509CertSign --CA rsa-ca rsa-server"
        rlRun "x509DumpCert ca" 0 "Root CA"
        rlRun "x509DumpCert rsa-ca" 0 "Intermediate RSA CA"
        rlRun "x509DumpCert rsa-server" 0 "Server RSA certificate"
        rlLogInfo "Loading configuration..."

        i=0

        # We need to test TLS-1.3, TLS-1.2 with SHA256 and SHA384, and TLS-1.1

        # Test description
        declare -a C_TEST
        # GnuTLS priority strings
        declare -a C_PRIO
        # OpenSSL names for ciphers
        declare -a C_OPENSSL
        # protocol option for openssl
        declare -a C_OSSLPROTO


        if [[ $fips -ne 0 ]] && (rlIsRHEL '<9' || rlIsFedora '<39'); then
            C_TEST[$i]="TLS-1.1 SHA1-MD5 PRF"
            C_PRIO[$i]="NONE:+VERS-TLS1.1:+AES-256-CBC:+SHA1:+RSA:+SIGN-ALL"
            C_OPENSSL[$i]="AES256-SHA"
            C_OSSLPROTO[$i]='-tls1_1'
            i=$(($i+1))
        fi

        C_TEST[$i]="TLS-1.2 SHA1 PRF"
        C_PRIO[$i]="NONE:+VERS-TLS1.2:+AES-128-CBC:+AEAD:+SHA1:+ECDHE-RSA:+SIGN-ALL:+GROUP-ALL"
        C_OPENSSL[$i]="ECDHE-RSA-AES128-SHA"
        C_OSSLPROTO[$i]='-tls1_2'
        i=$(($i+1))

        C_TEST[$i]="TLS-1.2 SHA256 PRF"
        C_PRIO[$i]="NONE:+VERS-TLS1.2:+AES-128-GCM:+AEAD:+SHA256:+ECDHE-RSA:+SIGN-ALL:+GROUP-ALL"
        C_OPENSSL[$i]="ECDHE-RSA-AES128-GCM-SHA256"
        C_OSSLPROTO[$i]='-tls1_2'
        i=$(($i+1))

        C_TEST[$i]="TLS-1.2 SHA384 PRF"
        C_PRIO[$i]="NONE:+VERS-TLS1.2:+AES-256-GCM:+AEAD:+SHA384:+ECDHE-RSA:+SIGN-ALL:+GROUP-ALL"
        C_OPENSSL[$i]="ECDHE-RSA-AES256-GCM-SHA384"
        C_OSSLPROTO[$i]='-tls1_2'
        i=$(($i+1))

        C_TEST[$i]="TLS-1.3 HKDF SHA256 PRF"
        C_PRIO[$i]="NONE:+VERS-TLS1.3:+AES-128-GCM:+AEAD:+SHA256:+ECDHE-RSA:+SIGN-ALL:+GROUP-ALL"
        C_OPENSSL[$i]="DEFAULT"
        C_OSSLPROTO[$i]='-tls1_3 -ciphersuites TLS_AES_128_GCM_SHA256'
        i=$(($i+1))

        C_TEST[$i]="TLS-1.3 HKDF SHA384 PRF"
        C_PRIO[$i]="NONE:+VERS-TLS1.3:+AES-256-GCM:+AEAD:+SHA384:+ECDHE-RSA:+SIGN-ALL:+GROUP-ALL"
        C_OPENSSL[$i]="DEFAULT"
        C_OSSLPROTO[$i]='-tls1_3 -ciphersuites TLS_AES_256_GCM_SHA384'
        i=$(($i+1))


        C_SUBCA="$(x509Cert rsa-ca)"
        C_CERT="$(x509Cert rsa-server)"
        C_KEY="$(x509Key rsa-server)"

        rlLogInfo "Configuration loaded"
    rlPhaseEnd

    for j in ${!C_TEST[@]}; do
        if [[ "${C_TEST[$j]}" = "TLS-1.1 SHA1-MD5 PRF" ]] && \
                (rlIsFedora && ! rlIsFedora '<33'); then
            rlPhaseStartTest 'Switching to LEGACY (Fedora 33+)'
                PREV_CRYPTO_POLICY=$(update-crypto-policies --show)
                rlRun "update-crypto-policies --set LEGACY"
            rlPhaseEnd
        fi

        rlPhaseStartTest "OpenSSL server GnuTLS client ${C_TEST[$j]}"
            options=(openssl s_server)
            options+=(-key ${C_KEY} -cert ${C_CERT})
            options+=(-CAfile "<(cat $(x509Cert ca) ${C_SUBCA})")
            options+=(-cipher ${C_OPENSSL[$j]})
            options+=(${C_OSSLPROTO[$j]})
            # We use some non-default len to test also the length parameter
            options+=(-keymatexport myLabel -keymatexportlen 42)
            rlRun "expect openssl-server.expect ${options[*]} \
                   >server.log 2>server.err &"
            openssl_pid=$!
            rlRun "rlWaitForSocket 4433 -p $openssl_pid"

            options=(gnutls-cli --verbose)
            options+=(--x509cafile $(x509Cert ca))
            options+=(--priority ${C_PRIO[j]})
            options+=(--keymatexport=myLabel --keymatexportsize=42)
            options+=(-p 4433 localhost)
            rlRun -s "expect gnutls-client.expect ${options[*]}"
            rlAssertGrep "client hello" $rlRun_LOG
            rlAssertGrep "server hello" $rlRun_LOG
            rlRun "cp $rlRun_LOG client.log"
            rlRun "kill $openssl_pid" 0
            rlRun "rlWait -s SIGKILL $openssl_pid" 0
            if ! rlGetPhaseState; then
                rlRun "cat server.log" 0 "Server stdout"
                rlRun "cat server.err" 0 "Server stderr"
            fi

            rlAssertGrep "Key material" client.log
            rlAssertGrep "Keying material" server.log
            rlRun "grep '^- Key material: ' client.log | sed -e 's/^.*: \([[:alnum:]]*\).*/\1/' -e 'y/abcdef/ABCDEF/' | tee client.key"
            rlRun "grep '^    Keying material: ' server.log | sed -e 's/^.*: \([[:alnum:]]*\).*/\1/' -e 'y/abcdef/ABCDEF/' | tee server.key"
            rlRun "cmp -s client.key server.key" 0 "Compare client and server key material."
        rlPhaseEnd

        rlPhaseStartTest "GnuTLS server OpenSSL client ${C_TEST[$j]}"
            options=(gnutls-serv --echo -p 4433)
            options+=(--priority ${C_PRIO[j]})
            options+=(--x509keyfile ${C_KEY})
            options+=(--x509certfile "<(cat ${C_CERT} ${C_SUBCA})")
            # We use some non-default len to test also the length parameter
            options+=(--keymatexport=myLabel --keymatexportsize=51)
            options+=(">server.log" "2>server.err" "&")
            rlRun "${options[*]}"
            gnutls_pid=$!
            rlRun "rlWaitForSocket 4433 -p $gnutls_pid"

            options=(openssl s_client)
            options+=(-CAfile $(x509Cert ca))
            options+=(-cipher ${C_OPENSSL[$j]})
            options+=(${C_OSSLPROTO[$j]})
            options+=(-keymatexport myLabel -keymatexportlen 51)
            options+=(-connect localhost:4433)
            rlRun -s "expect openssl-client.expect ${options[*]}"
            rlAssertGrep "client hello" $rlRun_LOG
            rlRun "[[ $(grep 'client hello' $rlRun_LOG | wc -l) -eq 2 ]]" 0 \
                "Check if server echo'ed back our message"
            rlRun "cp $rlRun_LOG client.log"
            rlRun "kill $gnutls_pid"
            rlRun "rlWait -s SIGKILL $gnutls_pid" 1
            if ! rlGetPhaseState; then
                rlRun "cat server.log" 0 "Server stdout"
                rlRun "cat server.err" 0 "Server stderr"
            fi

            rlAssertGrep "Key material" server.log
            rlAssertGrep "Keying material" client.log
            rlRun "grep '^- Key material: ' server.log | sed -e 's/^.*: \([[:alnum:]]*\).*/\1/' -e 'y/abcdef/ABCDEF/' | tee server.key"
            rlRun "grep '^    Keying material: ' client.log | sed -e 's/^.*: \([[:alnum:]]*\).*/\1/' -e 'y/abcdef/ABCDEF/' | tee client.key"
            rlRun "cmp -s client.key server.key" 0 "Compare client and server key material."
        rlPhaseEnd

        if [[ "${C_TEST[$j]}" = "TLS-1.1 SHA1-MD5 PRF" ]] && \
                (rlIsFedora && ! rlIsFedora '<33'); then
            rlPhaseStartTest 'Switching back from LEGACY (Fedora 33+)'
                rlRun "update-crypto-policies --set $PREV_CRYPTO_POLICY"
            rlPhaseEnd
        fi
    done


    rlPhaseStartCleanup
        rlRun "popd"
        rlRun "rm -r $TmpDir" 0 "Removing tmp directory"
    rlPhaseEnd
rlJournalPrintText
rlJournalEnd
