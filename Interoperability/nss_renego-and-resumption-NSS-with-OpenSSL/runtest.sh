#!/bin/bash
# vim: dict+=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/nss/Interoperability/renego-and-resumption-NSS-with-OpenSSL
#   Description: Verify that renegotiation and resumption between NSS and OpenSSL works
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

PACKAGE="nss"
PACKAGES="nss openssl"

SERVER_UTIL="/usr/lib64/nss/unsupported-tools/selfserv"
CLIENT_UTIL="/usr/lib64/nss/unsupported-tools/tstclnt"
STRSCLNT_UTIL="/usr/lib64/nss/unsupported-tools/strsclnt"
[ ! -f $SERVER_UTIL ] && SERVER_UTIL="/usr/lib/nss/unsupported-tools/selfserv"
[ ! -f $CLIENT_UTIL ] && CLIENT_UTIL="/usr/lib/nss/unsupported-tools/tstclnt"
[ ! -f $STRSCLNT_UTIL ] && STRSCLNT_UTIL="/usr/lib/nss/unsupported-tools/strsclnt"

NSS_POLICY="/etc/crypto-policies/back-ends/nss.config"

rlJournalStart
    rlPhaseStartSetup
        rlAssertRpm --all
        rlRun "rlImport certgen"
        rlRun "TmpDir=\$(mktemp -d)" 0 "Creating tmp directory"
        rlRun "cp nss-{client,server}.expect nss-client-normal.expect openssl-client.expect openssl-client-renego.expect rfc7919-ffdhe2048.pem openssl-client-resume.expect $TmpDir"
        rlRun "pushd $TmpDir"
        rlRun "rlImport fips"
        fipsIsEnabled
        _fips=$?
        if [[ $_fips -eq 0 ]]; then
            rlLogInfo "FIPS enabled"
        elif [[ $_fips -eq 1 ]]; then
            rlLogInfo "FIPS disabled"
        else
            rlDie "FIPS misconfigured"
            exit 1
        fi
        if rlIsRHEL && ( ! rlIsRHEL '<9' ) && [[ $_fips -eq 0 ]]; then
            # while the FIPS policy disables the CBC ciphersuites, they're
            # not actually disallowed in FIPS mode, so re-enable them
            # for more comprehensive interoperability test coverage
            old_policy=$(update-crypto-policies --show)
            rlRun "rlFileBackup --clean /etc/crypto-policies/policies/modules"
            echo -e 'cipher = AES-128-CBC+ AES-256-CBC+\n mac = HMAC-SHA1+' \
                > /etc/crypto-policies/policies/modules/UNFIPS.pmod
            rlRun 'update-crypto-policies --set FIPS:UNFIPS'
        elif ! rlIsRHEL '<8' && [[ $_fips -eq 1 ]]; then
            # we're checking for interoperability so we need to enable
            # everything supported
            # (unless we're in FIPS mode, then we can't touch policy files)
            old_policy="$(update-crypto-policies --show)"
            rlRun "update-crypto-policies --set LEGACY"
            # Camellia is not part of any policy so enable it explicitly in NSS:
            rlRun "rlFileBackup '$NSS_POLICY'"
            rlRun "sed -i 's/aes128-cbc:/aes128-cbc:camellia256-cbc:camellia128-cbc:/' $NSS_POLICY"
        elif rlIsRHEL 7 && rlIsRHEL '>=7.7'; then
            # because we are testing interoperability, not what ciphers are
            # enabled by default, overrride the policy and enable RC4
            rlRun "rlFileBackup --namespace rhel77 /etc/pki/nss-legacy/nss-rhel7.config"
            rlRun "sed -i 's/:RC4//' /etc/pki/nss-legacy/nss-rhel7.config"
        fi
        rlRun "x509KeyGen ca"
        rlRun "x509KeyGen rsa-ca"
        rlRun "x509KeyGen -t ecdsa ecdsa-ca"
        rlRun "x509KeyGen rsa-server"
        rlRun "x509KeyGen -t ecdsa ecdsa-server"
        rlRun "x509KeyGen rsa-client"
        rlRun "x509KeyGen -t ecdsa ecdsa-client"
        rlRun "x509SelfSign ca"
        rlRun "x509CertSign --CA ca -t ca --DN 'CN=RSA CA' rsa-ca"
        rlRun "x509CertSign --CA ca -t ca --DN 'CN=ECDSA CA' ecdsa-ca"
        rlRun "x509CertSign --CA rsa-ca rsa-server"
        rlRun "x509CertSign --CA ecdsa-ca ecdsa-server"
        rlRun "x509CertSign --CA rsa-ca -t webclient rsa-client"
        rlRun "x509CertSign --CA ecdsa-ca -t webclient ecdsa-client"
        rlRun "x509DumpCert ca" 0 "Root CA"
        rlRun "x509DumpCert rsa-ca" 0 "Intermediate RSA CA"
        rlRun "x509DumpCert ecdsa-ca" 0 "Intermediate ECDSA CA"
        rlRun "x509DumpCert rsa-server" 0 "Server RSA certificate"
        rlRun "x509DumpCert ecdsa-server" 0 "Server ECDSA certificate"
        rlRun "x509DumpCert rsa-client" 0 "Client RSA certificate"
        rlRun "x509DumpCert ecdsa-client" 0 "Client ECDSA certificate"
        # not needed on RHEL-8 FIPS mode
        if rlIsRHEL '<8' || [[ $_fips -eq 1 ]]; then
            rlRun "x509KeyGen -t dsa dsa-ca"
            rlRun "x509KeyGen -t dsa dsa-server"
            rlRun "x509KeyGen -t dsa dsa-client"
            rlRun "x509CertSign --CA ca -t ca --DN 'CN=DSA CA' dsa-ca"
            rlRun "x509CertSign --CA dsa-ca dsa-server"
            rlRun "x509CertSign --CA dsa-ca -t webclient dsa-client"
            rlRun "x509DumpCert dsa-ca" 0 "Intermediate DSA CA"
            rlRun "x509DumpCert dsa-server" 0 "Server DSA certificate"
            rlRun "x509DumpCert dsa-client" 0 "Client DSA certificate"
        fi
        rlLogInfo "Loading configuration..."

        i=0
        # IETF names for ciphers
        declare -a C_NAME
        # OpenSSL names for ciphers
        declare -a C_OPENSSL
        # hex ID of ciphersuite (NSS ID)
        declare -a C_ID
        # intermediate CA used
        declare -a C_SUBCA
        # EE certificate used
        declare -a C_CERT
        # EE key used
        declare -a C_KEY

        # RC4 and Camellia are disallowed in FIPS mode
        if [[ $_fips -eq 1 ]]; then
            if rlIsRHEL '<8'; then
                # MD5 HMAC deprecated in RHEL-8
                C_NAME[$i]="TLS_RSA_WITH_RC4_128_MD5"
                C_OPENSSL[$i]="RC4-MD5"
                C_ID[$i]="0004"
                C_TLS1_2_ONLY[$i]="False"
                C_SUBCA[$i]="$(x509Cert rsa-ca)"
                C_CERT[$i]="$(x509Cert rsa-server)"
                C_KEY[$i]="$(x509Key rsa-server)"
                C_CLNT_CERT[$i]="$(x509Cert rsa-client)"
                C_CLNT_KEY[$i]="$(x509Key rsa-client)"
                i=$(($i+1))
            fi

            if rlIsRHEL '<9'; then
                # RC4 is disabled in RHEL-9
                C_NAME[$i]="TLS_RSA_WITH_RC4_128_SHA"
                C_OPENSSL[$i]="RC4-SHA"
                C_ID[$i]="0005"
                C_TLS1_2_ONLY[$i]="False"
                C_SUBCA[$i]="$(x509Cert rsa-ca)"
                C_CERT[$i]="$(x509Cert rsa-server)"
                C_KEY[$i]="$(x509Key rsa-server)"
                C_CLNT_CERT[$i]="$(x509Cert rsa-client)"
                C_CLNT_KEY[$i]="$(x509Key rsa-client)"
                i=$(($i+1))

                C_NAME[$i]="TLS_ECDHE_RSA_WITH_RC4_128_SHA"
                C_OPENSSL[$i]="ECDHE-RSA-RC4-SHA"
                C_ID[$i]="C011"
                C_TLS1_2_ONLY[$i]="False"
                C_SUBCA[$i]="$(x509Cert rsa-ca)"
                C_CERT[$i]="$(x509Cert rsa-server)"
                C_KEY[$i]="$(x509Key rsa-server)"
                C_CLNT_CERT[$i]="$(x509Cert rsa-client)"
                C_CLNT_KEY[$i]="$(x509Key rsa-client)"
                i=$(($i+1))

                C_NAME[$i]="TLS_ECDHE_ECDSA_WITH_RC4_128_SHA"
                C_OPENSSL[$i]="ECDHE-ECDSA-RC4-SHA"
                C_ID[$i]="C007"
                C_TLS1_2_ONLY[$i]="False"
                C_SUBCA[$i]="$(x509Cert ecdsa-ca)"
                C_CERT[$i]="$(x509Cert ecdsa-server)"
                C_KEY[$i]="$(x509Key ecdsa-server)"
                C_CLNT_CERT[$i]="$(x509Cert ecdsa-client)"
                C_CLNT_KEY[$i]="$(x509Key ecdsa-client)"
                i=$(($i+1))
            fi

            C_NAME[$i]="TLS_RSA_WITH_CAMELLIA_128_CBC_SHA"
            C_OPENSSL[$i]="CAMELLIA128-SHA"
            C_ID[$i]="0041"
            C_TLS1_2_ONLY[$i]="False"
            C_SUBCA[$i]="$(x509Cert rsa-ca)"
            C_CERT[$i]="$(x509Cert rsa-server)"
            C_KEY[$i]="$(x509Key rsa-server)"
            C_CLNT_CERT[$i]="$(x509Cert rsa-client)"
            C_CLNT_KEY[$i]="$(x509Key rsa-client)"
            i=$(($i+1))

            if rlIsRHEL '<9'; then
                # DSS is disabled in RHEL-9
                C_NAME[$i]="TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA"
                C_OPENSSL[$i]="DHE-DSS-CAMELLIA128-SHA"
                C_ID[$i]="0044"
                C_TLS1_2_ONLY[$i]="False"
                C_SUBCA[$i]="$(x509Cert dsa-ca)"
                C_CERT[$i]="$(x509Cert dsa-server)"
                C_KEY[$i]="$(x509Key dsa-server)"
                C_CLNT_CERT[$i]="$(x509Cert dsa-client)"
                C_CLNT_KEY[$i]="$(x509Key dsa-client)"
                i=$(($i+1))
            fi

            C_NAME[$i]="TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA"
            C_OPENSSL[$i]="DHE-RSA-CAMELLIA128-SHA"
            C_ID[$i]="0045"
            C_TLS1_2_ONLY[$i]="False"
            C_SUBCA[$i]="$(x509Cert rsa-ca)"
            C_CERT[$i]="$(x509Cert rsa-server)"
            C_KEY[$i]="$(x509Key rsa-server)"
            C_CLNT_CERT[$i]="$(x509Cert rsa-client)"
            C_CLNT_KEY[$i]="$(x509Key rsa-client)"
            i=$(($i+1))
        fi

        # FIPS mode on RHEL-8 does not allow kRSA
        if ! (! rlIsRHEL '<8' && [[ $_fips -eq 0 ]]); then
            C_NAME[$i]="TLS_RSA_WITH_AES_128_CBC_SHA"
            C_OPENSSL[$i]="AES128-SHA"
            C_ID[$i]="002F"
            C_TLS1_2_ONLY[$i]="False"
            C_SUBCA[$i]="$(x509Cert rsa-ca)"
            C_CERT[$i]="$(x509Cert rsa-server)"
            C_KEY[$i]="$(x509Key rsa-server)"
            C_CLNT_CERT[$i]="$(x509Cert rsa-client)"
            C_CLNT_KEY[$i]="$(x509Key rsa-client)"
            i=$(($i+1))

            C_NAME[$i]="TLS_RSA_WITH_AES_256_CBC_SHA256"
            C_OPENSSL[$i]="AES256-SHA256"
            C_ID[$i]="003D"
            C_TLS1_2_ONLY[$i]="True"
            C_SUBCA[$i]="$(x509Cert rsa-ca)"
            C_CERT[$i]="$(x509Cert rsa-server)"
            C_KEY[$i]="$(x509Key rsa-server)"
            C_CLNT_CERT[$i]="$(x509Cert rsa-client)"
            C_CLNT_KEY[$i]="$(x509Key rsa-client)"
            i=$(($i+1))

            C_NAME[$i]="TLS_RSA_WITH_AES_128_GCM_SHA256"
            C_OPENSSL[$i]="AES128-GCM-SHA256"
            C_ID[$i]="009C"
            C_TLS1_2_ONLY[$i]="True"
            C_SUBCA[$i]="$(x509Cert rsa-ca)"
            C_CERT[$i]="$(x509Cert rsa-server)"
            C_KEY[$i]="$(x509Key rsa-server)"
            C_CLNT_CERT[$i]="$(x509Cert rsa-client)"
            C_CLNT_KEY[$i]="$(x509Key rsa-client)"
            i=$(($i+1))

            # NSS on RHEL-6 does not support SHA-384 PRF
            if ! rlIsRHEL 6; then
                C_NAME[$i]="TLS_RSA_WITH_AES_256_GCM_SHA384"
                C_OPENSSL[$i]="AES256-GCM-SHA384"
                C_ID[$i]="009D"
                C_TLS1_2_ONLY[$i]="True"
                C_SUBCA[$i]="$(x509Cert rsa-ca)"
                C_CERT[$i]="$(x509Cert rsa-server)"
                C_KEY[$i]="$(x509Key rsa-server)"
                C_CLNT_CERT[$i]="$(x509Cert rsa-client)"
                C_CLNT_KEY[$i]="$(x509Key rsa-client)"
                i=$(($i+1))
            fi
        fi

        C_NAME[$i]="TLS_DHE_RSA_WITH_AES_128_CBC_SHA"
        C_OPENSSL[$i]="DHE-RSA-AES128-SHA"
        C_ID[$i]="0033"
        C_TLS1_2_ONLY[$i]="False"
        C_SUBCA[$i]="$(x509Cert rsa-ca)"
        C_CERT[$i]="$(x509Cert rsa-server)"
        C_KEY[$i]="$(x509Key rsa-server)"
        C_CLNT_CERT[$i]="$(x509Cert rsa-client)"
        C_CLNT_KEY[$i]="$(x509Key rsa-client)"
        i=$(($i+1))

        C_NAME[$i]="TLS_DHE_RSA_WITH_AES_256_CBC_SHA256"
        C_OPENSSL[$i]="DHE-RSA-AES256-SHA256"
        C_ID[$i]="006B"
        C_TLS1_2_ONLY[$i]="True"
        C_SUBCA[$i]="$(x509Cert rsa-ca)"
        C_CERT[$i]="$(x509Cert rsa-server)"
        C_KEY[$i]="$(x509Key rsa-server)"
        C_CLNT_CERT[$i]="$(x509Cert rsa-client)"
        C_CLNT_KEY[$i]="$(x509Key rsa-client)"
        i=$(($i+1))

        C_NAME[$i]="TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"
        C_OPENSSL[$i]="DHE-RSA-AES128-GCM-SHA256"
        C_ID[$i]="009E"
        C_TLS1_2_ONLY[$i]="True"
        C_SUBCA[$i]="$(x509Cert rsa-ca)"
        C_CERT[$i]="$(x509Cert rsa-server)"
        C_KEY[$i]="$(x509Key rsa-server)"
        C_CLNT_CERT[$i]="$(x509Cert rsa-client)"
        C_CLNT_KEY[$i]="$(x509Key rsa-client)"
        i=$(($i+1))

        if ! rlIsRHEL 6; then
            C_NAME[$i]="TLS_DHE_RSA_WITH_AES_256_GCM_SHA384"
            C_OPENSSL[$i]="DHE-RSA-AES256-GCM-SHA384"
            C_ID[$i]="009F"
            C_TLS1_2_ONLY[$i]="True"
            C_SUBCA[$i]="$(x509Cert rsa-ca)"
            C_CERT[$i]="$(x509Cert rsa-server)"
            C_KEY[$i]="$(x509Key rsa-server)"
            C_CLNT_CERT[$i]="$(x509Cert rsa-client)"
            C_CLNT_KEY[$i]="$(x509Key rsa-client)"
            i=$(($i+1))
        fi

        # FIPS mode on RHEL-8 does not allow DSA
        # as does RHEL-9
        if ! (! rlIsRHEL '<8' && [[ $fips -eq 0 ]] ) && rlIsRHEL '<9'; then
            C_NAME[$i]="TLS_DHE_DSS_WITH_AES_128_CBC_SHA"
            C_OPENSSL[$i]="DHE-DSS-AES128-SHA"
            C_ID[$i]="0032"
            C_TLS1_2_ONLY[$i]="False"
            C_SUBCA[$i]="$(x509Cert dsa-ca)"
            C_CERT[$i]="$(x509Cert dsa-server)"
            C_KEY[$i]="$(x509Key dsa-server)"
            C_CLNT_CERT[$i]="$(x509Cert dsa-client)"
            C_CLNT_KEY[$i]="$(x509Key dsa-client)"
            i=$(($i+1))

            C_NAME[$i]="TLS_DHE_DSS_WITH_AES_256_CBC_SHA256"
            C_OPENSSL[$i]="DHE-DSS-AES256-SHA256"
            C_ID[$i]="006A"
            C_TLS1_2_ONLY[$i]="True"
            C_SUBCA[$i]="$(x509Cert dsa-ca)"
            C_CERT[$i]="$(x509Cert dsa-server)"
            C_KEY[$i]="$(x509Key dsa-server)"
            C_CLNT_CERT[$i]="$(x509Cert dsa-client)"
            C_CLNT_KEY[$i]="$(x509Key dsa-client)"
            i=$(($i+1))

            C_NAME[$i]="TLS_DHE_DSS_WITH_AES_128_GCM_SHA256"
            C_OPENSSL[$i]="DHE-DSS-AES128-GCM-SHA256"
            C_ID[$i]="00A2"
            C_TLS1_2_ONLY[$i]="True"
            C_SUBCA[$i]="$(x509Cert dsa-ca)"
            C_CERT[$i]="$(x509Cert dsa-server)"
            C_KEY[$i]="$(x509Key dsa-server)"
            C_CLNT_CERT[$i]="$(x509Cert dsa-client)"
            C_CLNT_KEY[$i]="$(x509Key dsa-client)"
            i=$(($i+1))

            if ! rlIsRHEL 6; then
                C_NAME[$i]="TLS_DHE_DSS_WITH_AES_256_GCM_SHA384"
                C_OPENSSL[$i]="DHE-DSS-AES256-GCM-SHA384"
                C_ID[$i]="00A3"
                C_TLS1_2_ONLY[$i]="True"
                C_SUBCA[$i]="$(x509Cert dsa-ca)"
                C_CERT[$i]="$(x509Cert dsa-server)"
                C_KEY[$i]="$(x509Key dsa-server)"
                C_CLNT_CERT[$i]="$(x509Cert dsa-client)"
                C_CLNT_KEY[$i]="$(x509Key dsa-client)"
                i=$(($i+1))
            fi
        fi

        # FIPS mode on RHEL-8 does not allow 3DES
        if ! (! rlIsRHEL '<8' && [[ $fips -eq 0 ]] ); then
            C_NAME[$i]="TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"
            C_OPENSSL[$i]="ECDHE-RSA-DES-CBC3-SHA"
            C_ID[$i]="C012"
            C_TLS1_2_ONLY[$i]="False"
            C_SUBCA[$i]="$(x509Cert rsa-ca)"
            C_CERT[$i]="$(x509Cert rsa-server)"
            C_KEY[$i]="$(x509Key rsa-server)"
            C_CLNT_CERT[$i]="$(x509Cert rsa-client)"
            C_CLNT_KEY[$i]="$(x509Key rsa-client)"
            i=$(($i+1))
        fi

        if ! rlIsRHEL 6; then
            C_NAME[$i]="TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384"
            C_OPENSSL[$i]="ECDHE-RSA-AES256-SHA384"
            C_ID[$i]="C028"
            C_TLS1_2_ONLY[$i]="True"
            C_SUBCA[$i]="$(x509Cert rsa-ca)"
            C_CERT[$i]="$(x509Cert rsa-server)"
            C_KEY[$i]="$(x509Key rsa-server)"
            C_CLNT_CERT[$i]="$(x509Cert rsa-client)"
            C_CLNT_KEY[$i]="$(x509Key rsa-client)"
            i=$(($i+1))
        fi

        C_NAME[$i]="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
        C_OPENSSL[$i]="ECDHE-RSA-AES128-GCM-SHA256"
        C_ID[$i]="C02F"
        C_TLS1_2_ONLY[$i]="True"
        C_SUBCA[$i]="$(x509Cert rsa-ca)"
        C_CERT[$i]="$(x509Cert rsa-server)"
        C_KEY[$i]="$(x509Key rsa-server)"
        C_CLNT_CERT[$i]="$(x509Cert rsa-client)"
        C_CLNT_KEY[$i]="$(x509Key rsa-client)"
        i=$(($i+1))

        if ! rlIsRHEL 6; then
            C_NAME[$i]="TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
            C_OPENSSL[$i]="ECDHE-RSA-AES256-GCM-SHA384"
            C_ID[$i]="C030"
            C_TLS1_2_ONLY[$i]="True"
            C_SUBCA[$i]="$(x509Cert rsa-ca)"
            C_CERT[$i]="$(x509Cert rsa-server)"
            C_KEY[$i]="$(x509Key rsa-server)"
            C_CLNT_CERT[$i]="$(x509Cert rsa-client)"
            C_CLNT_KEY[$i]="$(x509Key rsa-client)"
            i=$(($i+1))
        fi

        C_NAME[$i]="TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"
        C_OPENSSL[$i]="ECDHE-ECDSA-AES256-SHA"
        C_ID[$i]="C00A"
        C_TLS1_2_ONLY[$i]="False"
        C_SUBCA[$i]="$(x509Cert ecdsa-ca)"
        C_CERT[$i]="$(x509Cert ecdsa-server)"
        C_KEY[$i]="$(x509Key ecdsa-server)"
        C_CLNT_CERT[$i]="$(x509Cert ecdsa-client)"
        C_CLNT_KEY[$i]="$(x509Key ecdsa-client)"
        i=$(($i+1))

        C_NAME[$i]="TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"
        C_OPENSSL[$i]="ECDHE-ECDSA-AES128-SHA256"
        C_ID[$i]="C023"
        C_TLS1_2_ONLY[$i]="True"
        C_SUBCA[$i]="$(x509Cert ecdsa-ca)"
        C_CERT[$i]="$(x509Cert ecdsa-server)"
        C_KEY[$i]="$(x509Key ecdsa-server)"
        C_CLNT_CERT[$i]="$(x509Cert ecdsa-client)"
        C_CLNT_KEY[$i]="$(x509Key ecdsa-client)"
        i=$(($i+1))

        C_NAME[$i]="TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
        C_OPENSSL[$i]="ECDHE-ECDSA-AES128-GCM-SHA256"
        C_ID[$i]="C02B"
        C_TLS1_2_ONLY[$i]="True"
        C_SUBCA[$i]="$(x509Cert ecdsa-ca)"
        C_CERT[$i]="$(x509Cert ecdsa-server)"
        C_KEY[$i]="$(x509Key ecdsa-server)"
        C_CLNT_CERT[$i]="$(x509Cert ecdsa-client)"
        C_CLNT_KEY[$i]="$(x509Key ecdsa-client)"
        i=$(($i+1))

        if ! rlIsRHEL 6; then
            C_NAME[$i]="TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
            C_OPENSSL[$i]="ECDHE-ECDSA-AES256-GCM-SHA384"
            C_ID[$i]="C02C"
            C_TLS1_2_ONLY[$i]="True"
            C_SUBCA[$i]="$(x509Cert ecdsa-ca)"
            C_CERT[$i]="$(x509Cert ecdsa-server)"
            C_KEY[$i]="$(x509Key ecdsa-server)"
            C_CLNT_CERT[$i]="$(x509Cert ecdsa-client)"
            C_CLNT_KEY[$i]="$(x509Key ecdsa-client)"
            i=$(($i+1))
        fi

        # TLS 1.1 is disallowed in FIPS mode on RHEL-8
        if ! rlIsRHEL '<8' && [[ $fips -eq 0 ]]; then
            protocols=("tls1_2")
        else
            protocols=("tls1_2" "tls1_1")
        fi

        rlLogInfo "Configuration loaded"

        rlRun "mkdir ca-db" 0 "Directory with just CA certificate"
        rlRun "certutil -N --empty-password -d sql:./ca-db" 0 "Create database for CA cert"
        rlRun "certutil -A -d sql:./ca-db -n ca -t 'cC,,' -a -i $(x509Cert ca)"\
            0 "Import CA certificate"
    rlPhaseEnd

    for j in ${!C_NAME[@]}; do
      for prot in "${protocols[@]}"; do

        # skip tests of TLSv1.2 specific ciphers when testing TLSv1.1
        if [[ $prot == "tls1_1" ]] && [[ ${C_TLS1_2_ONLY[$j]} == "True" ]]; then
            continue
        fi

        rlPhaseStartTest "OpenSSL server NSS client ${C_NAME[$j]} cipher $prot protocol"
            options=(openssl s_server -www -key ${C_KEY[$j]})
            options+=(-cert ${C_CERT[$j]})
            options+=(-CAfile '<(cat $(x509Cert ca) ${C_SUBCA[$j]})')
            options+=(-cipher ${C_OPENSSL[$j]})
            if [[ $(echo ${C_NAME[$j]}  | awk -F"_" '{print $2}') == "DHE" ]] && fipsIsEnabled; then
                options+=(-dhparam rfc7919-ffdhe2048.pem)
            fi
            rlRun "${options[*]} >server.log 2>server.err &"
            openssl_pid=$!
            rlRun "rlWaitForSocket 4433 -p $openssl_pid"
            options=(${CLIENT_UTIL})
            options+=(-h localhost -p 4433)
            options+=(-d sql:./ca-db/)
            options+=(-c :${C_ID[$j]})
            if [[ $prot == "tls1_2" ]]; then
                options+=(-V tls1.0:tls1.2)
                version=1.2
            else
                options+=(-V tls1.0:tls1.1)
                version=1.1
            fi
            rlRun -s "expect nss-client-normal.expect ${options[*]}"
            if rlIsRHEL '<8'; then
                rlAssertGrep "New, TLSv1/SSLv3," "$rlRun_LOG"
            else
                # in RHEL-8 that returns the protocol version of the *cipher*
                rlAssertGrep "New, (TLS|SSL)" "$rlRun_LOG" -E
                rlAssertGrep "Protocol  : TLSv$version" "$rlRun_LOG"
            fi
            rlRun "kill $openssl_pid"
            rlRun "rlWait -s SIGKILL $openssl_pid" 143
            if ! rlGetPhaseState; then
                rlRun "cat server.log" 0 "Server stdout"
                rlRun "cat server.err" 0 "Server stderr"
            fi
        rlPhaseEnd

        rlPhaseStartTest "OpenSSL server NSS client ${C_NAME[$j]} cipher $prot protocol client auth"
            rlLogInfo "Preparing NSS database"
            rlRun "mkdir nssdb/"
            rlRun "certutil -N --empty-password -d sql:./nssdb/"
            rlRun "certutil -A -d sql:./nssdb/ -n ca -t 'cC,,' -a -i $(x509Cert ca)"
            rlRun "certutil -A -d sql:./nssdb/ -n subca -t ',,' -a -i ${C_SUBCA[$j]}"
            clnt_nickname="${C_CLNT_KEY[$j]%%/*}"
            rlRun "pk12util -i $(x509Key --pkcs12 --with-cert $clnt_nickname) -d sql:./nssdb -W ''"

            rlLogInfo "Test proper"
            options=(openssl s_server -www -key ${C_KEY[$j]})
            options+=(-cert ${C_CERT[$j]})
            options+=(-CAfile '<(cat $(x509Cert ca) ${C_SUBCA[$j]})')
            options+=(-cipher ${C_OPENSSL[$j]})
            options+=(-Verify 1 -verify_return_error)
            if [[ $(echo ${C_NAME[$j]}  | awk -F"_" '{print $2}') == "DHE" ]] && fipsIsEnabled; then
                options+=(-dhparam rfc7919-ffdhe2048.pem)
            fi
            rlRun "${options[*]} >server.log 2>server.err &"
            openssl_pid=$!
            rlRun "rlWaitForSocket 4433 -p $openssl_pid"
            options=(${CLIENT_UTIL})
            options+=(-h localhost -p 4433)
            options+=(-d sql:./nssdb/)
            options+=(-c :${C_ID[$j]})
            if [[ $prot == "tls1_2" ]]; then
                options+=(-V tls1.0:tls1.2)
                version=1.2
            else
                options+=(-V tls1.0:tls1.1)
                version=1.1
            fi
            options+=(-n $clnt_nickname)
            rlRun -s "expect nss-client-normal.expect ${options[*]}"
            if rlIsRHEL '<8'; then
                rlAssertGrep "New, TLSv1/SSLv3," "$rlRun_LOG"
            else
                rlAssertGrep "New, (SSL|TLS)" "$rlRun_LOG" -E
                rlAssertGrep "Protocol  : TLSv$version" "$rlRun_LOG"
            fi
            rlRun "kill $openssl_pid"
            rlRun "rlWait -s SIGKILL $openssl_pid" 143
            if ! rlGetPhaseState; then
                rlRun "cat server.log" 0 "Server stdout"
                rlRun "cat server.err" 0 "Server stderr"
            fi
            rlRun "rm -rf nssdb/"
        rlPhaseEnd


        rlPhaseStartTest "OpenSSL server NSS client ${C_NAME[$j]} cipher $prot protocol renegotiation"
            options=(openssl s_server -www -key ${C_KEY[$j]})
            options+=(-cert ${C_CERT[$j]})
            options+=(-CAfile '<(cat $(x509Cert ca) ${C_SUBCA[$j]})')
            options+=(-cipher ${C_OPENSSL[$j]})
            if ! rlIsRHEL '<9'; then
                options+=(-client_renegotiation)
            fi
            if [[ $(echo ${C_NAME[$j]}  | awk -F"_" '{print $2}') == "DHE" ]] && fipsIsEnabled; then
                options+=(-dhparam rfc7919-ffdhe2048.pem)
            fi
            rlRun "${options[*]} >server.log 2>server.err &"
            openssl_pid=$!
            rlRun "rlWaitForSocket 4433 -p $openssl_pid"
            options=(${CLIENT_UTIL})
            options+=(-h localhost -p 4433)
            options+=(-d sql:./ca-db/)
            options+=(-c :${C_ID[$j]})
            options+=(-r 1)
            if [[ $prot == "tls1_2" ]]; then
                options+=(-V tls1.0:tls1.2)
                version=1.2
            else
                options+=(-V tls1.0:tls1.1)
                version=1.1
            fi
            rlRun -s "expect nss-client.expect ${options[*]}"
            if rlIsRHEL '<8'; then
                rlAssertGrep "New, TLSv1/SSLv3," "$rlRun_LOG"
            else
                rlAssertGrep "New, (SSL|TLS)" "$rlRun_LOG" -E
                rlAssertGrep "Protocol  : TLSv$version" "$rlRun_LOG"
            fi
            rlRun "kill $openssl_pid"
            rlRun "rlWait -s SIGKILL $openssl_pid" 143
            if ! rlGetPhaseState; then
                rlRun "cat server.log" 0 "Server stdout"
                rlRun "cat server.err" 0 "Server stderr"
            fi
        rlPhaseEnd

        rlPhaseStartTest "OpenSSL server NSS client ${C_NAME[$j]} cipher $prot protocol client auth renegotiation"
            rlLogInfo "Preparing NSS database"
            rlRun "mkdir nssdb/"
            rlRun "certutil -N --empty-password -d sql:./nssdb/"
            rlRun "certutil -A -d sql:./nssdb/ -n ca -t 'cC,,' -a -i $(x509Cert ca)"
            rlRun "certutil -A -d sql:./nssdb/ -n subca -t ',,' -a -i ${C_SUBCA[$j]}"
            clnt_nickname="${C_CLNT_KEY[$j]%%/*}"
            rlRun "pk12util -i $(x509Key --pkcs12 --with-cert $clnt_nickname) -d sql:./nssdb -W ''"

            rlLogInfo "Test proper"
            options=(openssl s_server -www -key ${C_KEY[$j]})
            options+=(-cert ${C_CERT[$j]})
            options+=(-CAfile '<(cat $(x509Cert ca) ${C_SUBCA[$j]})')
            options+=(-cipher ${C_OPENSSL[$j]})
            options+=(-Verify 1 -verify_return_error)
            if ! rlIsRHEL '<9'; then
                options+=(-client_renegotiation)
            fi
            if [[ $(echo ${C_NAME[$j]}  | awk -F"_" '{print $2}') == "DHE" ]] && fipsIsEnabled; then
                options+=(-dhparam rfc7919-ffdhe2048.pem)
            fi
            rlRun "${options[*]} >server.log 2>server.err &"
            openssl_pid=$!
            rlRun "rlWaitForSocket 4433 -p $openssl_pid"
            options=(${CLIENT_UTIL})
            options+=(-h localhost -p 4433)
            options+=(-d sql:./nssdb/)
            options+=(-c :${C_ID[$j]})
            options+=(-r 1)
            if [[ $prot == "tls1_2" ]]; then
                options+=(-V tls1.0:tls1.2)
                version=1.2
            else
                options+=(-V tls1.0:tls1.1)
                version=1.1
            fi
            options+=(-n $clnt_nickname)
            rlRun -s "expect nss-client.expect ${options[*]}"
            if rlIsRHEL '<8'; then
                rlAssertGrep "New, TLSv1/SSLv3," "$rlRun_LOG"
            else
                rlAssertGrep "New, (SSL|TLS)" "$rlRun_LOG" -E
                rlAssertGrep "Protocol  : TLSv$version" "$rlRun_LOG"
            fi
            rlRun "kill $openssl_pid"
            rlRun "rlWait -s SIGKILL $openssl_pid" 143
            if ! rlGetPhaseState; then
                rlRun "cat server.log" 0 "Server stdout"
                rlRun "cat server.err" 0 "Server stderr"
            fi
            rlRun "rm -rf nssdb/"
        rlPhaseEnd

      for sess in sessionID ticket; do
        rlPhaseStartTest "OpenSSL server NSS client ${C_NAME[$j]} cipher $prot protocol $sess resumption"
            options=(openssl s_server -www -key ${C_KEY[$j]})
            options+=(-cert ${C_CERT[$j]})
            options+=(-CAfile '<(cat $(x509Cert ca) ${C_SUBCA[$j]})')
            options+=(-cipher ${C_OPENSSL[$j]})
            if [[ $(echo ${C_NAME[$j]}  | awk -F"_" '{print $2}') == "DHE" ]] && fipsIsEnabled; then
                options+=(-dhparam rfc7919-ffdhe2048.pem)
            fi
            rlRun "${options[*]} >server.log 2>server.err &"
            openssl_pid=$!
            rlRun "rlWaitForSocket 4433 -p $openssl_pid"
            options=($STRSCLNT_UTIL)
            options+=(-p 4433)
            options+=(-d sql:./ca-db/)
            options+=(-c 100 -P 20)
            options+=(-C :${C_ID[$j]})
            if [[ $sess == ticket ]]; then
                options+=(-u)
            fi
            if [[ $prot == "tls1_2" ]]; then
                options+=(-V tls1.0:tls1.2)
            else
                options+=(-V tls1.0:tls1.1)
            fi
            options+=(localhost)
            rlRun -s "rlWatchdog '${options[*]}' 60"
            rlAssertGrep "80 cache hits" "$rlRun_LOG"
            if [[ $sess == ticket ]]; then
                rlAssertGrep "80 stateless resumes" $rlRun_LOG
            else
                rlAssertGrep "0 stateless resumes" $rlRun_LOG
            fi
            rlRun "kill $openssl_pid"
            rlRun "rlWait -s SIGKILL $openssl_pid" 143
            if ! rlGetPhaseState; then
                rlRun "cat server.log" 0 "Server stdout"
                rlRun "cat server.err" 0 "Server stderr"
            fi
        rlPhaseEnd
      done

      for sess in sessionID ticket; do
        rlPhaseStartTest "OpenSSL server NSS client ${C_NAME[$j]} cipher $prot protocol client auth $sess resumption"
            rlLogInfo "Preparing NSS database"
            rlRun "mkdir nssdb/"
            rlRun "certutil -N --empty-password -d sql:./nssdb/"
            rlRun "certutil -A -d sql:./nssdb/ -n ca -t 'cC,,' -a -i $(x509Cert ca)"
            rlRun "certutil -A -d sql:./nssdb/ -n subca -t ',,' -a -i ${C_SUBCA[$j]}"
            clnt_nickname="${C_CLNT_KEY[$j]%%/*}"
            rlRun "pk12util -i $(x509Key --pkcs12 --with-cert $clnt_nickname) -d sql:./nssdb -W ''"

            rlLogInfo "Test proper"
            options=(openssl s_server -www -key ${C_KEY[$j]})
            options+=(-cert ${C_CERT[$j]})
            options+=(-CAfile '<(cat $(x509Cert ca) ${C_SUBCA[$j]})')
            options+=(-cipher ${C_OPENSSL[$j]})
            options+=(-Verify 1 -verify_return_error)
            if [[ $(echo ${C_NAME[$j]}  | awk -F"_" '{print $2}') == "DHE" ]] && fipsIsEnabled; then
                options+=(-dhparam rfc7919-ffdhe2048.pem)
            fi
            rlRun "${options[*]} >server.log 2>server.err &"
            openssl_pid=$!
            rlRun "rlWaitForSocket 4433 -p $openssl_pid"
            options=($STRSCLNT_UTIL)
            options+=(-p 4433)
            options+=(-d sql:./nssdb/)
            options+=(-c 100 -P 20)
            options+=(-C :${C_ID[$j]})
            options+=(-n $clnt_nickname)
            if [[ $sess == ticket ]]; then
                options+=(-u)
            fi
            if [[ $prot == "tls1_2" ]]; then
                options+=(-V tls1.0:tls1.2)
            else
                options+=(-V tls1.0:tls1.1)
            fi
            options+=(localhost)
            rlRun -s "rlWatchdog '${options[*]}' 60"
            rlAssertGrep "80 cache hits" "$rlRun_LOG"
            if [[ $sess == ticket ]]; then
                rlAssertGrep "80 stateless resumes" $rlRun_LOG
            else
                rlAssertGrep "0 stateless resumes" $rlRun_LOG
            fi
            rlRun "kill $openssl_pid"
            rlRun "rlWait -s SIGKILL $openssl_pid" 143
            if ! rlGetPhaseState; then
                rlRun "cat server.log" 0 "Server stdout"
                rlRun "cat server.err" 0 "Server stderr"
            fi
            rlRun "rm -rf nssdb/"
        rlPhaseEnd
      done

        rlPhaseStartTest "NSS server OpenSSL client ${C_NAME[$j]} cipher $prot protocol"
            rlLogInfo "Preparing NSS database"
            rlRun "mkdir nssdb/"
            rlRun "certutil -N --empty-password -d sql:./nssdb/"
            rlRun "certutil -A -d sql:./nssdb/ -n ca -t 'cC,,' -a -i $(x509Cert ca)"
            rlRun "certutil -A -d sql:./nssdb/ -n subca -t ',,' -a -i ${C_SUBCA[$j]}"
            rlRun "pk12util -i $(x509Key --pkcs12 --with-cert ${C_KEY[$j]%%/*}) -d sql:./nssdb -W ''"

            rlLogInfo "Test proper"
            declare -a options=()
            options+=(${SERVER_UTIL} -d sql:./nssdb/ -p 4433 -V tls1.0:tls1.2
                      -c :${C_ID[$j]} -H 1)
            if [[ ${C_KEY[$j]} =~ 'ecdsa' ]]; then
                options+=(-e ${C_KEY[$j]%%/*})
            elif [[ ${C_KEY[$j]} =~ 'dsa' ]]; then
                options+=(-S ${C_KEY[$j]%%/*})
            else
                options+=(-n ${C_KEY[$j]%%/*})
            fi
            rlRun "expect nss-server.expect ${options[*]} >server.log 2>server.err &"
            nss_pid=$!
            rlRun "rlWaitForSocket 4433 -p $nss_pid"
            options=(openssl s_client)
            options+=(-CAfile $(x509Cert ca))
            options+=(-cipher ${C_OPENSSL[$j]})
            options+=(-connect localhost:4433)
            if [[ $prot == "tls1_1" ]]; then
                options+=(-tls1_1)
            else
                options+=(-tls1_2)
            fi
            rlRun -s "expect openssl-client.expect ${options[*]}"
            rlAssertGrep "GET / HTTP/1.0" "$rlRun_LOG"
            rlAssertGrep "Server: Generic Web Server" "$rlRun_LOG"
            rlRun "kill $nss_pid"
            rlRun "rlWait -s SIGKILL $nss_pid" 0,143
            if ! rlGetPhaseState; then
                rlRun "cat server.log" 0 "Server stdout"
                rlRun "cat server.err" 0 "Server stderr"
            fi
            rlRun "rm -rf nssdb/" 0 "Clean up NSS database"
        rlPhaseEnd

        rlPhaseStartTest "NSS server OpenSSL client ${C_NAME[$j]} cipher $prot protocol client auth"
            rlLogInfo "Preparing NSS database"
            rlRun "mkdir nssdb/"
            rlRun "certutil -N --empty-password -d sql:./nssdb/"
            rlRun "certutil -A -d sql:./nssdb/ -n ca -t 'cCT,,' -a -i $(x509Cert ca)"
            rlRun "certutil -A -d sql:./nssdb/ -n subca -t ',,' -a -i ${C_SUBCA[$j]}"
            rlRun "pk12util -i $(x509Key --pkcs12 --with-cert ${C_KEY[$j]%%/*}) -d sql:./nssdb -W ''"

            rlLogInfo "Test proper"
            declare -a options=()
            options+=(${SERVER_UTIL} -d sql:./nssdb/ -p 4433 -V tls1.0:tls1.2 -rr
                      -c :${C_ID[$j]} -H 1)
            if [[ ${C_KEY[$j]} =~ 'ecdsa' ]]; then
                options+=(-e ${C_KEY[$j]%%/*})
            elif [[ ${C_KEY[$j]} =~ 'dsa' ]]; then
                options+=(-S ${C_KEY[$j]%%/*})
            else
                options+=(-n ${C_KEY[$j]%%/*})
            fi
            rlRun "expect nss-server.expect ${options[*]} >server.log 2>server.err &"
            nss_pid=$!
            rlRun "rlWaitForSocket 4433 -p $nss_pid"
            options=(openssl s_client)
            options+=(-CAfile $(x509Cert ca))
            options+=(-cipher ${C_OPENSSL[$j]})
            options+=(-connect localhost:4433)
            options+=(-cert ${C_CLNT_CERT[$j]} -key ${C_CLNT_KEY[$j]})
            if [[ $prot == "tls1_1" ]]; then
                options+=(-tls1_1)
            else
                options+=(-tls1_2)
            fi
            rlRun -s "expect openssl-client.expect ${options[*]}"
            rlAssertGrep "GET / HTTP/1.0" "$rlRun_LOG"
            rlAssertGrep "Server: Generic Web Server" "$rlRun_LOG"
            rlRun "kill $nss_pid"
            rlRun "rlWait -s SIGKILL $nss_pid" 0,143
            if ! rlGetPhaseState; then
                rlRun "cat server.log" 0 "Server stdout"
                rlRun "cat server.err" 0 "Server stderr"
            fi
            rlRun "rm -rf nssdb/" 0 "Clean up NSS database"
        rlPhaseEnd

        rlPhaseStartTest "NSS server OpenSSL client ${C_NAME[$j]} cipher $prot protocol renegotiation"
            rlLogInfo "Preparing NSS database"
            rlRun "mkdir nssdb/"
            rlRun "certutil -N --empty-password -d sql:./nssdb/"
            rlRun "certutil -A -d sql:./nssdb/ -n ca -t 'cC,,' -a -i $(x509Cert ca)"
            rlRun "certutil -A -d sql:./nssdb/ -n subca -t ',,' -a -i ${C_SUBCA[$j]}"
            rlRun "pk12util -i $(x509Key --pkcs12 --with-cert ${C_KEY[$j]%%/*}) -d sql:./nssdb -W ''"

            rlLogInfo "Test proper"
            declare -a options=()
            options+=(${SERVER_UTIL} -d sql:./nssdb/ -p 4433 -V tls1.0:tls1.2
                      -c :${C_ID[$j]} -H 1)
            if [[ ${C_KEY[$j]} =~ 'ecdsa' ]]; then
                options+=(-e ${C_KEY[$j]%%/*})
            elif [[ ${C_KEY[$j]} =~ 'dsa' ]]; then
                options+=(-S ${C_KEY[$j]%%/*})
            else
                options+=(-n ${C_KEY[$j]%%/*})
            fi
            rlRun "expect nss-server.expect ${options[*]} >server.log 2>server.err &"
            nss_pid=$!
            rlRun "rlWaitForSocket 4433 -p $nss_pid"
            options=(openssl s_client)
            options+=(-CAfile $(x509Cert ca))
            options+=(-cipher ${C_OPENSSL[$j]})
            options+=(-connect localhost:4433)
            if [[ $prot == "tls1_1" ]]; then
                options+=(-tls1_1)
            else
                options+=(-tls1_2)
            fi
            rlRun -s "expect openssl-client-renego.expect ${options[*]}"
            rlRun "kill $nss_pid"
            rlRun "rlWait -s SIGKILL $nss_pid" 0,143
            rlAssertGrep "RENEGOTIATING" "$rlRun_LOG"
            rlRun "grep -A 10 RENEGOTIATING $rlRun_LOG | grep 'verify return:1'"
            if ! rlGetPhaseState; then
                rlRun "cat server.log" 0 "Server stdout"
                rlRun "cat server.err" 0 "Server stderr"
            fi
            rlRun "rm -rf nssdb/" 0 "Clean up NSS database"
        rlPhaseEnd

        rlPhaseStartTest "NSS server OpenSSL client ${C_NAME[$j]} cipher $prot protocol client auth renegotiation"
            rlLogInfo "Preparing NSS database"
            rlRun "mkdir nssdb/"
            rlRun "certutil -N --empty-password -d sql:./nssdb/"
            rlRun "certutil -A -d sql:./nssdb/ -n ca -t 'cCT,,' -a -i $(x509Cert ca)"
            rlRun "certutil -A -d sql:./nssdb/ -n subca -t ',,' -a -i ${C_SUBCA[$j]}"
            rlRun "pk12util -i $(x509Key --pkcs12 --with-cert ${C_KEY[$j]%%/*}) -d sql:./nssdb -W ''"

            rlLogInfo "Test proper"
            declare -a options=()
            options+=(${SERVER_UTIL} -d sql:./nssdb/ -p 4433 -V tls1.0:tls1.2 -rr
                      -c :${C_ID[$j]} -H 1)
            if [[ ${C_KEY[$j]} =~ 'ecdsa' ]]; then
                options+=(-e ${C_KEY[$j]%%/*})
            elif [[ ${C_KEY[$j]} =~ 'dsa' ]]; then
                options+=(-S ${C_KEY[$j]%%/*})
            else
                options+=(-n ${C_KEY[$j]%%/*})
            fi
            rlRun "expect nss-server.expect ${options[*]} >server.log 2>server.err &"
            nss_pid=$!
            rlRun "rlWaitForSocket 4433 -p $nss_pid"
            options=(openssl s_client)
            options+=(-CAfile $(x509Cert ca))
            options+=(-cipher ${C_OPENSSL[$j]})
            options+=(-connect localhost:4433)
            options+=(-cert ${C_CLNT_CERT[$j]} -key ${C_CLNT_KEY[$j]})
            if [[ $prot == "tls1_1" ]]; then
                options+=(-tls1_1)
            else
                options+=(-tls1_2)
            fi
            rlRun -s "expect openssl-client-renego.expect ${options[*]}"
            rlRun "kill $nss_pid"
            rlRun "rlWait -s SIGKILL $nss_pid" 0,143
            rlAssertGrep "RENEGOTIATING" "$rlRun_LOG"
            rlRun "grep -A 10 RENEGOTIATING $rlRun_LOG | grep 'verify return:1'"
            if ! rlGetPhaseState; then
                rlRun "cat server.log" 0 "Server stdout"
                rlRun "cat server.err" 0 "Server stderr"
            fi
            rlRun "rm -rf nssdb/" 0 "Clean up NSS database"
        rlPhaseEnd

    for sess in sessionID ticket; do
        rlPhaseStartTest "NSS server OpenSSL client ${C_NAME[$j]} cipher $prot protocol $sess resumption"
            rlLogInfo "Preparing NSS database"
            rlRun "mkdir nssdb/"
            rlRun "certutil -N --empty-password -d sql:./nssdb/"
            rlRun "certutil -A -d sql:./nssdb/ -n ca -t 'cC,,' -a -i $(x509Cert ca)"
            rlRun "certutil -A -d sql:./nssdb/ -n subca -t ',,' -a -i ${C_SUBCA[$j]}"
            rlRun "pk12util -i $(x509Key --pkcs12 --with-cert ${C_KEY[$j]%%/*}) -d sql:./nssdb -W ''"

            rlLogInfo "Test proper"
            declare -a options=()
            options+=(${SERVER_UTIL} -d sql:./nssdb/ -p 4433 -V tls1.0:tls1.2
                      -c :${C_ID[$j]} -H 1)
            if [[ $sess == "ticket" ]]; then
                options+=(-u)
            fi
            if [[ ${C_KEY[$j]} =~ 'ecdsa' ]]; then
                options+=(-e ${C_KEY[$j]%%/*})
            elif [[ ${C_KEY[$j]} =~ 'dsa' ]]; then
                options+=(-S ${C_KEY[$j]%%/*})
            else
                options+=(-n ${C_KEY[$j]%%/*})
            fi
            rlRun "expect nss-server.expect ${options[*]} >server.log 2>server.err &"
            nss_pid=$!
            rlRun "rlWaitForSocket 4433 -p $nss_pid"
            options=(openssl s_client)
            options+=(-CAfile $(x509Cert ca))
            options+=(-cipher ${C_OPENSSL[$j]})
            options+=(-connect localhost:4433)
            if [[ $sess == "sessionID" ]]; then
                options+=(-no_ticket)
            fi
            if [[ $prot == "tls1_1" ]]; then
                options+=(-tls1_1)
                version=1.1
            else
                options+=(-tls1_2)
                version=1.2
            fi
            rlRun -s "expect openssl-client-resume.expect ${options[*]} -sess_out sess.pem"
            if rlIsRHEL '<8'; then
                rlAssertGrep "New, TLSv1/SSLv3," "$rlRun_LOG"
                rlAssertNotGrep "Reused, TLSv1/SSLv3," "$rlRun_LOG"
            else
                rlAssertGrep "New, (SSL|TLS)" "$rlRun_LOG" -E
                rlAssertNotGrep "Reused, (SSL|TLS)" "$rlRun_LOG" -E
                rlAssertGrep "Protocol  : TLSv$version" "$rlRun_LOG"
            fi
            rlAssertGrep "Verify return code: 0 (ok)" $rlRun_LOG
            rlRun -s "expect openssl-client-resume.expect ${options[*]} -sess_in sess.pem </dev/null"
            if [[ ${C_NAME[$j]} =~ _DSS_ ]]; then
                rlLogInfo "Old RHEL detected: Expecting RHBZ#1397365 and RHBZ#1397478 to be NOT fixed"
                rlAssertNotGrep "Reused, (TLS|SSL)" $rlRun_LOG -E
                rlAssertGrep "New, (TLS|SSL)" $rlRun_LOG -E
                rlAssertGrep "Protocol  : TLSv$version" "$rlRun_LOG"
            else
                rlAssertGrep "Reused, (SSL|TLS)" "$rlRun_LOG" -E
                rlAssertNotGrep "New, (SSL|TLS)" "$rlRun_LOG" -E
                rlAssertGrep "Protocol  : TLSv$version" "$rlRun_LOG"
            fi
            rlAssertGrep "Verify return code: 0 (ok)" $rlRun_LOG
            rlRun "kill $nss_pid"
            rlRun "rlWait -s SIGKILL $nss_pid" 0,143
            if ! rlGetPhaseState; then
                rlRun "cat server.log" 0 "Server stdout"
                rlRun "cat server.err" 0 "Server stderr"
            fi
            rlRun "rm -rf nssdb/" 0 "Clean up NSS database"
        rlPhaseEnd
    done

    for sess in sessionID ticket; do
        rlPhaseStartTest "NSS server OpenSSL client ${C_NAME[$j]} cipher $prot protocol client auth $sess resumption"
            rlLogInfo "Preparing NSS database"
            rlRun "mkdir nssdb/"
            rlRun "certutil -N --empty-password -d sql:./nssdb/"
            rlRun "certutil -A -d sql:./nssdb/ -n ca -t 'cCT,,' -a -i $(x509Cert ca)"
            rlRun "certutil -A -d sql:./nssdb/ -n subca -t ',,' -a -i ${C_SUBCA[$j]}"
            rlRun "pk12util -i $(x509Key --pkcs12 --with-cert ${C_KEY[$j]%%/*}) -d sql:./nssdb -W ''"

            rlLogInfo "Test proper"
            declare -a options=()
            options+=(${SERVER_UTIL} -d sql:./nssdb/ -p 4433 -V tls1.0:tls1.2 -rr
                      -c :${C_ID[$j]} -H 1)
            if [[ $sess == "ticket" ]]; then
                options+=(-u)
            fi
            if [[ ${C_KEY[$j]} =~ 'ecdsa' ]]; then
                options+=(-e ${C_KEY[$j]%%/*})
            elif [[ ${C_KEY[$j]} =~ 'dsa' ]]; then
                options+=(-S ${C_KEY[$j]%%/*})
            else
                options+=(-n ${C_KEY[$j]%%/*})
            fi
            rlRun "expect nss-server.expect ${options[*]} >server.log 2>server.err &"
            nss_pid=$!
            rlRun "rlWaitForSocket 4433 -p $nss_pid"
            options=(openssl s_client)
            options+=(-CAfile $(x509Cert ca))
            options+=(-cipher ${C_OPENSSL[$j]})
            options+=(-connect localhost:4433)
            options+=(-cert ${C_CLNT_CERT[$j]} -key ${C_CLNT_KEY[$j]})
            if [[ $sess == "sessionID" ]]; then
                options+=(-no_ticket)
            fi
            if [[ $prot == "tls1_1" ]]; then
                options+=(-tls1_1)
                version=1.1
            else
                options+=(-tls1_2)
                version=1.2
            fi
            rlRun -s "expect openssl-client-resume.expect ${options[*]} -sess_out sess.pem"
            if rlIsRHEL '<8'; then
                rlAssertGrep "New, TLSv1/SSLv3," "$rlRun_LOG"
                rlAssertNotGrep "Reused, TLSv1/SSLv3," "$rlRun_LOG"
            else
                rlAssertGrep "New, (SSL|TLS)" "$rlRun_LOG" -E
                rlAssertNotGrep "Reused, (SSL|TLS)" "$rlRun_LOG" -E
                rlAssertGrep "Protocol  : TLSv$version" "$rlRun_LOG"
            fi
            rlAssertGrep "Verify return code: 0 (ok)" $rlRun_LOG
            rlRun -s "expect openssl-client-resume.expect ${options[*]} -sess_in sess.pem"
            if [[ ${C_NAME[$j]} =~ _DSS_ ]]; then
                rlLogInfo "Old RHEL detected: Expecting RHBZ#1397365 and RHBZ#1397478 to be NOT fixed"
                rlAssertNotGrep "Reused, (SSL|TLS)" "$rlRun_LOG" -E
                rlAssertGrep "New, (SSL|TLS)" "$rlRun_LOG" -E
                rlAssertGrep "Protocol  : TLSv$version" "$rlRun_LOG"
            else
                rlAssertGrep "Reused, (SSL|TLS)" "$rlRun_LOG" -E
                rlAssertNotGrep "New, (SSL|TLS)" "$rlRun_LOG" -E
                rlAssertGrep "Protocol  : TLSv$version" "$rlRun_LOG"
            fi
            rlAssertGrep "Verify return code: 0 (ok)" $rlRun_LOG
            rlRun "kill $nss_pid"
            rlRun "rlWait -s SIGKILL $nss_pid" 0,143
            if ! rlGetPhaseState; then
                rlRun "cat server.log" 0 "Server stdout"
                rlRun "cat server.err" 0 "Server stderr"
            fi
            rlRun "rm -rf nssdb/" 0 "Clean up NSS database"
        rlPhaseEnd
    done

      done
    done

    rlPhaseStartCleanup
        if [[ -n $old_policy ]]; then
            rlRun "update-crypto-policies --set $old_policy"
        fi
        if ! rlIsRHEL '<8' && [[ $_fips -eq 1 ]]; then
            rlRun "rlFileRestore"
        elif rlIsRHEL 7 && rlIsRHEL '>=7.7'; then
            rlRun "rlFileRestore --namespace rhel77"
        fi
        rlRun "popd"
        rlRun "rm -r $TmpDir" 0 "Removing tmp directory"
    rlPhaseEnd
rlJournalPrintText
rlJournalEnd
