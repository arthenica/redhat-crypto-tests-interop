#!/bin/bash
# vim: dict+=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/gnutls/Interoperability/TLSv1-2-with-OpenSSL
#   Description: Verify interoperability of GnuTLS TLSv1.2 with OpenSSL
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
        # in FIPS mode by default in testing we don't allow OpenSSL to generate
        # 1024 bit keys, but since we're not testing OpenSSL and we're
        # verifying that legacy code works, we can override this system wide
        # setting
        unset OPENSSL_ENFORCE_MODULUS_BITS
        # similarly, we want to check that the ciphers work, not if they are
        # supported, so overwrite the policy
        gnutls_prio="NORMAL"
        if ! rlIsRHEL '<8'; then
            # but we can change the policy only in normal mode, not FIPS
            if [[ $fips -ne 0 ]]; then
                current_policy=$(update-crypto-policies --show)
                rlRun "update-crypto-policies --set LEGACY"
                openssl_config=$(readlink /etc/crypto-policies/back-ends/openssl.config)
                rlRun "rlFileBackup $openssl_config"
                opensslcnf_config=$(readlink /etc/crypto-policies/back-ends/opensslcnf.config)
                rlRun "rlFileBackup $opensslcnf_config"
                rlRun "sed -i 's/-CAMELLIA/CAMELLIA/g' $openssl_config"
                rlRun "sed -i 's/-CAMELLIA/CAMELLIA/g' $opensslcnf_config"
                if ! rlIsRHEL '<9'; then
                    # while we don't support TLS 1.1 even in LEGACY in RHEL-9
                    # some customers may still force enable it, so do this sanity check
                    rlRun "sed -i 's/MinProtocol = TLSv1.2/MinProtocol = TLSv1.1/g' $opensslcnf_config"
                fi
                gnutls_config="/etc/crypto-policies/back-ends/gnutls.config"
                rlRun "rlFileBackup $(readlink $gnutls_config)"

                if rlIsRHEL; then
                    # In RHEL we need to override the 3DES setting because of RHBZ#1623490
                    rlRun "sed -i 's/+ECDHE-RSA:/+ECDHE-RSA:+CAMELLIA-128-CBC:+CAMELLIA-256-CBC:+3DES-CBC:+SHA256:+SHA384:/g' $gnutls_config"
                    if ! rlIsRHEL '<9'; then
                        rlRun "sed -i '/disabled-version = TLS1.1/d' $gnutls_config"
                    fi
                elif rlIsFedora; then
                    # In Fedora we have to allow CAMELLIA, DHE-DSS, DSA-SHA1 signatures, SHA-256 and SHA-384.
                    # TODO: DHE-DSS will be added to LEGACY in Fedora-32 timeframe or later:
                    # https://gitlab.com/redhat-crypto/fedora-crypto-policies/-/merge_requests/62/
                    rlRun "sed -i 's/^SYSTEM=\(.*\)$/SYSTEM=\1:+DHE-DSS:+CAMELLIA-128-CBC:+CAMELLIA-256-CBC:+SHA256:+SHA384:+SIGN-DSA-SHA1/g' $gnutls_config"
                    rlRun "sed -i '/tls-disabled-cipher = CAMELLIA.*/d' $gnutls_config"
                fi
            fi
            if rlIsRHEL '<9'; then
                gnutls_prio="@SYSTEM"
            else
                if [[ $fips -eq 1 ]]; then  # FIPS mode disabled
                    gnutls_prio="@SYSTEM:+SHA256:+SHA384"
                else  # FIPS mode enabled
                    current_policy=$(update-crypto-policies --show)
                    rlRun "rlFileBackup --clean /etc/crypto-policies/policies/modules"
                    echo 'cipher = AES-128-CBC+ AES-256-CBC+' >> /etc/crypto-policies/policies/modules/UNFIPS.pmod
                    echo 'key_exchange = RSA+' >> /etc/crypto-policies/policies/modules/UNFIPS.pmod
                    rlRun 'update-crypto-policies --set FIPS:UNFIPS'
                fi
            fi
        fi
        rlRun "x509KeyGen ca"
        rlRun "x509KeyGen rsa-ca"
        rlRun "x509KeyGen rsa-server"
        rlRun "x509KeyGen rsa-client"
        rlRun "x509SelfSign ca"
        rlRun "x509CertSign --CA ca -t ca --DN 'CN=RSA CA' rsa-ca"
        rlRun "x509CertSign --CA rsa-ca rsa-server"
        rlRun "x509CertSign --CA rsa-ca -t webclient rsa-client"
        rlRun "x509DumpCert ca" 0 "Root CA"
        rlRun "x509DumpCert rsa-ca" 0 "Intermediate RSA CA"
        rlRun "x509DumpCert rsa-server" 0 "Server RSA certificate"
        rlRun "x509DumpCert rsa-client" 0 "Client RSA certificate"
        # --conservative is as a workaround for RHBZ# 1238279 & 1238290
        # we don't test DSA in FIPS mode on RHEL-8
        # DSA is dropped on RHEL-9
        if ( [[ $fips -ne 0 ]] || rlIsRHEL '<8' ) && rlIsRHEL '<9'; then
            rlRun "x509KeyGen -t dsa --conservative -s 1024 1024dsa-ca"
            rlRun "x509KeyGen -t dsa --conservative -s 1024 1024dsa-server"
            rlRun "x509KeyGen -t dsa --conservative -s 1024 1024dsa-client"
            rlRun "x509CertSign --CA ca -t ca --DN 'CN=1024DSA CA' 1024dsa-ca"
            rlRun "x509CertSign --CA 1024dsa-ca --md sha1 1024dsa-server"
            rlRun "x509CertSign --CA 1024dsa-ca -t webclient --md sha1 1024dsa-client"
            rlRun "x509DumpCert 1024dsa-ca" 0 "Intermediate 1024DSA CA"
            rlRun "x509DumpCert 1024dsa-server" 0 "Server 1024DSA certificate"
            rlRun "x509DumpCert 1024dsa-client" 0 "Client 1024DSA certificate"
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

        #
        # RSA key exchange ciphers
        #
        # RC4 is disabled for TLS in RHEL-8
        # and is incompatible with FIPS mode
        if [[ $fips -ne 0 ]] && rlIsRHEL '<8'; then
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
        fi

        # CAMELLIA is FIPS incompatible and unsupported on RHEL-9
        if [[ $fips -ne 0 ]] && rlIsRHEL '<9'; then
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

            C_NAME[$i]="TLS_RSA_WITH_CAMELLIA_256_CBC_SHA"
            C_OPENSSL[$i]="CAMELLIA256-SHA"
            C_ID[$i]="0084"
            C_TLS1_2_ONLY[$i]="False"
            C_SUBCA[$i]="$(x509Cert rsa-ca)"
            C_CERT[$i]="$(x509Cert rsa-server)"
            C_KEY[$i]="$(x509Key rsa-server)"
            C_CLNT_CERT[$i]="$(x509Cert rsa-client)"
            C_CLNT_KEY[$i]="$(x509Key rsa-client)"
            i=$(($i+1))
        fi

        # RSA key exchange is disallowed in FIPS mode on RHEL-8
        if ! ( [[ $fips -eq 0 ]] && ! rlIsRHEL '<8'); then
            # 3DES is unsupported on RHEL-9
            if rlIsRHEL '<9'; then
                C_NAME[$i]="TLS_RSA_WITH_3DES_EDE_CBC_SHA"
                C_OPENSSL[$i]="DES-CBC3-SHA"
                C_ID[$i]="000A"
                C_TLS1_2_ONLY[$i]="False"
                C_SUBCA[$i]="$(x509Cert rsa-ca)"
                C_CERT[$i]="$(x509Cert rsa-server)"
                C_KEY[$i]="$(x509Key rsa-server)"
                C_CLNT_CERT[$i]="$(x509Cert rsa-client)"
                C_CLNT_KEY[$i]="$(x509Key rsa-client)"
                i=$(($i+1))
            fi

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

            C_NAME[$i]="TLS_RSA_WITH_AES_256_CBC_SHA"
            C_OPENSSL[$i]="AES256-SHA"
            C_ID[$i]="0035"
            C_TLS1_2_ONLY[$i]="False"
            C_SUBCA[$i]="$(x509Cert rsa-ca)"
            C_CERT[$i]="$(x509Cert rsa-server)"
            C_KEY[$i]="$(x509Key rsa-server)"
            C_CLNT_CERT[$i]="$(x509Cert rsa-client)"
            C_CLNT_KEY[$i]="$(x509Key rsa-client)"
            i=$(($i+1))

            C_NAME[$i]="TLS_RSA_WITH_AES_128_CBC_SHA256"
            C_OPENSSL[$i]="AES128-SHA256"
            C_ID[$i]="003C"
            C_TLS1_2_ONLY[$i]="True"
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
        fi

        #
        # FFDHE+RSA
        #

        # Camellia is unsupported on RHEL-9
        if [[ $fips -ne 0 ]] && rlIsRHEL '<9'; then
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

            C_NAME[$i]="TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA"
            C_OPENSSL[$i]="DHE-RSA-CAMELLIA256-SHA"
            C_ID[$i]="0088"
            C_TLS1_2_ONLY[$i]="False"
            C_SUBCA[$i]="$(x509Cert rsa-ca)"
            C_CERT[$i]="$(x509Cert rsa-server)"
            C_KEY[$i]="$(x509Key rsa-server)"
            C_CLNT_CERT[$i]="$(x509Cert rsa-client)"
            C_CLNT_KEY[$i]="$(x509Key rsa-client)"
            i=$(($i+1))
        fi

        # FIPS mode on RHEL-8 disallows 3DES
        if ! ( [[ $fips -eq 0 ]] && ! rlIsRHEL '<8') && rlIsRHEL '<9'; then
            C_NAME[$i]="TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA"
            C_OPENSSL[$i]="EDH-RSA-DES-CBC3-SHA"
            C_ID[$i]="0016"
            C_TLS1_2_ONLY[$i]="False"
            C_SUBCA[$i]="$(x509Cert rsa-ca)"
            C_CERT[$i]="$(x509Cert rsa-server)"
            C_KEY[$i]="$(x509Key rsa-server)"
            C_CLNT_CERT[$i]="$(x509Cert rsa-client)"
            C_CLNT_KEY[$i]="$(x509Key rsa-client)"
            i=$(($i+1))
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

        C_NAME[$i]="TLS_DHE_RSA_WITH_AES_256_CBC_SHA"
        C_OPENSSL[$i]="DHE-RSA-AES256-SHA"
        C_ID[$i]="0039"
        C_TLS1_2_ONLY[$i]="False"
        C_SUBCA[$i]="$(x509Cert rsa-ca)"
        C_CERT[$i]="$(x509Cert rsa-server)"
        C_KEY[$i]="$(x509Key rsa-server)"
        C_CLNT_CERT[$i]="$(x509Cert rsa-client)"
        C_CLNT_KEY[$i]="$(x509Key rsa-client)"
        i=$(($i+1))

        # CBC-SHA256 is disabled because of the possible side-channel attacks
        if ! ( [[ $fips -eq 0 ]] && ! rlIsRHEL '<8' ); then
            C_NAME[$i]="TLS_DHE_RSA_WITH_AES_128_CBC_SHA256"
            C_OPENSSL[$i]="DHE-RSA-AES128-SHA256"
            C_ID[$i]="0067"
            C_TLS1_2_ONLY[$i]="True"
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
        fi

        #
        # FFDHE+DSS
        #
        # since 2048bit DSA is undefined for TLS1.1, use 1024bit DSA
        # for cipher suites, RHBZ#1238333

        # DSA/DSS is dropped on RHEL-9
        if rlIsRHEL '<9'; then

        # camellia is FIPS incompatible
        if [[ $fips -ne 0 ]]; then
            C_NAME[$i]="TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA"
            C_OPENSSL[$i]="DHE-DSS-CAMELLIA128-SHA"
            C_ID[$i]="0044"
            C_TLS1_2_ONLY[$i]="False"
            C_SUBCA[$i]="$(x509Cert 1024dsa-ca)"
            C_CERT[$i]="$(x509Cert 1024dsa-server)"
            C_KEY[$i]="$(x509Key 1024dsa-server)"
            C_CLNT_CERT[$i]="$(x509Cert 1024dsa-client)"
            C_CLNT_KEY[$i]="$(x509Key 1024dsa-client)"
            i=$(($i+1))

            C_NAME[$i]="TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA"
            C_OPENSSL[$i]="DHE-DSS-CAMELLIA256-SHA"
            C_ID[$i]="0087"
            C_TLS1_2_ONLY[$i]="False"
            C_SUBCA[$i]="$(x509Cert 1024dsa-ca)"
            C_CERT[$i]="$(x509Cert 1024dsa-server)"
            C_KEY[$i]="$(x509Key 1024dsa-server)"
            C_CLNT_CERT[$i]="$(x509Cert 1024dsa-client)"
            C_CLNT_KEY[$i]="$(x509Key 1024dsa-client)"
            i=$(($i+1))
        fi

        # DSA is disabled in FIPS mode on RHEL-8
        if ! ( [[ $fips -eq 0 ]] && ! rlIsRHEL '<8' ); then
            if rlIsRHEL '<9'; then
                C_NAME[$i]="TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA"
                C_OPENSSL[$i]="EDH-DSS-DES-CBC3-SHA"
                C_ID[$i]="0013"
                C_TLS1_2_ONLY[$i]="False"
                C_SUBCA[$i]="$(x509Cert 1024dsa-ca)"
                C_CERT[$i]="$(x509Cert 1024dsa-server)"
                C_KEY[$i]="$(x509Key 1024dsa-server)"
                C_CLNT_CERT[$i]="$(x509Cert 1024dsa-client)"
                C_CLNT_KEY[$i]="$(x509Key 1024dsa-client)"
                i=$(($i+1))
            fi

            C_NAME[$i]="TLS_DHE_DSS_WITH_AES_128_CBC_SHA"
            C_OPENSSL[$i]="DHE-DSS-AES128-SHA"
            C_ID[$i]="0032"
            C_TLS1_2_ONLY[$i]="False"
            C_SUBCA[$i]="$(x509Cert 1024dsa-ca)"
            C_CERT[$i]="$(x509Cert 1024dsa-server)"
            C_KEY[$i]="$(x509Key 1024dsa-server)"
            C_CLNT_CERT[$i]="$(x509Cert 1024dsa-client)"
            C_CLNT_KEY[$i]="$(x509Key 1024dsa-client)"
            i=$(($i+1))

            C_NAME[$i]="TLS_DHE_DSS_WITH_AES_256_CBC_SHA"
            C_OPENSSL[$i]="DHE-DSS-AES256-SHA"
            C_ID[$i]="0038"
            C_TLS1_2_ONLY[$i]="False"
            C_SUBCA[$i]="$(x509Cert 1024dsa-ca)"
            C_CERT[$i]="$(x509Cert 1024dsa-server)"
            C_KEY[$i]="$(x509Key 1024dsa-server)"
            C_CLNT_CERT[$i]="$(x509Cert 1024dsa-client)"
            C_CLNT_KEY[$i]="$(x509Key 1024dsa-client)"
            i=$(($i+1))

            C_NAME[$i]="TLS_DHE_DSS_WITH_AES_128_CBC_SHA256"
            C_OPENSSL[$i]="DHE-DSS-AES128-SHA256"
            C_ID[$i]="0040"
            C_TLS1_2_ONLY[$i]="True"
            C_SUBCA[$i]="$(x509Cert 1024dsa-ca)"
            C_CERT[$i]="$(x509Cert 1024dsa-server)"
            C_KEY[$i]="$(x509Key 1024dsa-server)"
            C_CLNT_CERT[$i]="$(x509Cert 1024dsa-client)"
            C_CLNT_KEY[$i]="$(x509Key 1024dsa-client)"
            i=$(($i+1))

            C_NAME[$i]="TLS_DHE_DSS_WITH_AES_256_CBC_SHA256"
            C_OPENSSL[$i]="DHE-DSS-AES256-SHA256"
            C_ID[$i]="006A"
            C_TLS1_2_ONLY[$i]="True"
            C_SUBCA[$i]="$(x509Cert 1024dsa-ca)"
            C_CERT[$i]="$(x509Cert 1024dsa-server)"
            C_KEY[$i]="$(x509Key 1024dsa-server)"
            C_CLNT_CERT[$i]="$(x509Cert 1024dsa-client)"
            C_CLNT_KEY[$i]="$(x509Key 1024dsa-client)"
            i=$(($i+1))
        fi
        fi

        # RHEL-8 fips mode disallows TLS 1.1
        if [[ $fips -eq 0 ]] && ! rlIsRHEL '<8'; then
            protos=(tls1_2)
        # On 9 tls1.1 is not allowed, but it's still allowed in Fedora
        elif rlIsRHEL '<9' || rlIsFedora '<39'; then
            protos=(tls1_2 tls1_1)
        else
            protos=(tls1_2)
        fi

        rlLogInfo "Configuration loaded"
    rlPhaseEnd

    for j in ${!C_NAME[@]}; do
      for prot in "${protos[@]}"; do

        # skip ciphers that work only in TLS1.2 when testing TLS1.1
        if [[ $prot == tls1_1 ]] && [[ ${C_TLS1_2_ONLY[$j]} == "True" ]]; then
            continue
        fi

        rlPhaseStartTest "OpenSSL server GnuTLS client ${C_NAME[$j]} cipher $prot protocol"
            options=(openssl s_server)
            options+=(-key ${C_KEY[$j]} -cert ${C_CERT[$j]})
            options+=(-CAfile '<(cat $(x509Cert ca) ${C_SUBCA[$j]})')
            options+=(-cipher ${C_OPENSSL[$j]})
            rlRun "expect openssl-server.expect ${options[*]} \
                   >server.log 2>server.err &"
            openssl_pid=$!
            rlRun "rlWaitForSocket 4433 -p $openssl_pid"

            options=(gnutls-cli --verbose)
            options+=(--x509cafile $(x509Cert ca))
            if [[ $prot == tls1_2 ]]; then
                options+=(--priority $gnutls_prio:-VERS-ALL:+VERS-TLS1.2)
            fi
            if [[ $prot == tls1_1 ]]; then
                options+=(--priority $gnutls_prio:-VERS-ALL:+VERS-TLS1.1)
            fi
            options+=(-p 4433 localhost)
            rlRun -s "expect gnutls-client.expect ${options[*]}"
            rlAssertGrep "client hello" $rlRun_LOG
            rlAssertGrep "server hello" $rlRun_LOG
            if [[ $prot == tls1_1 ]]; then
                rlAssertGrep "Version: TLS1.1" $rlRun_LOG
            else
                rlAssertGrep "Version: TLS1.2" $rlRun_LOG
            fi
            rlRun "kill $openssl_pid" 0,1
            if ! rlGetPhaseState; then
                rlRun "cat server.log" 0 "Server stdout"
                rlRun "cat server.err" 0 "Server stderr"
            fi
            rlRun "rlWaitForSocket 4433 --close"
        rlPhaseEnd

        rlPhaseStartTest "GnuTLS server OpenSSL client ${C_NAME[$j]} cipher $prot protocol"
            options=(gnutls-serv --echo -p 4433)
            options+=(--priority $gnutls_prio:-VERS-ALL:+VERS-TLS1.1:+VERS-TLS1.2)
            options+=(--x509keyfile ${C_KEY[$j]})
            options+=(--x509certfile "<(cat ${C_CERT[$j]} ${C_SUBCA[$j]})")
            options+=(">server.log" "2>server.err" "&")
            rlRun "${options[*]}"
            gnutls_pid=$!
            rlRun "rlWaitForSocket 4433 -p $gnutls_pid"

            options=(openssl s_client)
            options+=(-CAfile $(x509Cert ca))
            options+=(-cipher ${C_OPENSSL[$j]})
            options+=(-connect localhost:4433)
            if [[ $prot == tls1_1 ]]; then
                options+=(-tls1_1)
            else
                options+=(-tls1_2)
            fi
            rlRun -s "expect openssl-client.expect ${options[*]}"
            rlAssertGrep "client hello" $rlRun_LOG
            rlRun "[[ $(grep 'client hello' $rlRun_LOG | wc -l) -eq 2 ]]" 0 \
                "Check if server echo'ed back our message"
            if [[ $prot == tls1_1 ]]; then
                rlAssertGrep "Protocol  : TLSv1.1" $rlRun_LOG
            else
                rlAssertGrep "Protocol  : TLSv1.2" $rlRun_LOG
            fi
            rlRun "kill $gnutls_pid"
            if ! rlGetPhaseState; then
                rlRun "cat server.log" 0 "Server stdout"
                rlRun "cat server.err" 0 "Server stderr"
            fi
            rlRun "rlWaitForSocket 4433 --close"
        rlPhaseEnd

        rlPhaseStartTest "OpenSSL server GnuTLS client ${C_NAME[$j]} cipher $prot protocol client cert"
            options=(openssl s_server)
            options+=(-key ${C_KEY[$j]} -cert ${C_CERT[$j]})
            options+=(-CAfile '<(cat $(x509Cert ca) ${C_SUBCA[$j]})')
            options+=(-cipher ${C_OPENSSL[$j]})
            options+=(-Verify 1)
            rlRun "expect openssl-server.expect ${options[*]} \
                   >server.log 2>server.err &"
            openssl_pid=$!
            rlRun "rlWaitForSocket 4433 -p $openssl_pid"

            options=(gnutls-cli --verbose)
            options+=(--x509cafile $(x509Cert ca))
            options+=(--x509keyfile ${C_CLNT_KEY[$j]})
            options+=(--x509certfile ${C_CLNT_CERT[$j]})
            if [[ $prot == tls1_2 ]]; then
                options+=(--priority $gnutls_prio:-VERS-ALL:+VERS-TLS1.2)
            fi
            if [[ $prot == tls1_1 ]]; then
                options+=(--priority $gnutls_prio:-VERS-ALL:+VERS-TLS1.1)
            fi
            options+=(-p 4433 localhost)
            rlRun -s "expect gnutls-client.expect ${options[*]}"
            rlAssertGrep "client hello" $rlRun_LOG
            rlAssertGrep "server hello" $rlRun_LOG
            if [[ $prot == tls1_1 ]]; then
                rlAssertGrep "Version: TLS1.1" $rlRun_LOG
            else
                rlAssertGrep "Version: TLS1.2" $rlRun_LOG
            fi
            rlRun "kill $openssl_pid" 0,1
            if ! rlGetPhaseState; then
                rlRun "cat server.log" 0 "Server stdout"
                rlRun "cat server.err" 0 "Server stderr"
            fi
            rlRun "rlWaitForSocket 4433 --close"
        rlPhaseEnd

        rlPhaseStartTest "GnuTLS server OpenSSL client ${C_NAME[$j]} cipher $prot protocol client cert"
            options=(gnutls-serv --echo -p 4433)
            options+=(--priority $gnutls_prio:+VERS-TLS1.2)
            options+=(--x509keyfile ${C_KEY[$j]})
            options+=(--x509certfile "<(cat ${C_CERT[$j]} ${C_SUBCA[$j]})")
            options+=(--x509cafile "<(cat $(x509Cert ca) ${C_SUBCA[$j]})")
            if rlIsRHEL '6'; then
                options+=(--require-cert)
            else
                options+=(--require-client-cert --verify-client-cert)
            fi
            options+=(">server.log" "2>server.err" "&")
            rlRun "${options[*]}"
            gnutls_pid=$!
            rlRun "rlWaitForSocket 4433 -p $gnutls_pid"

            options=(openssl s_client)
            options+=(-CAfile $(x509Cert ca))
            options+=(-cipher ${C_OPENSSL[$j]})
            options+=(-key ${C_CLNT_KEY[$j]})
            options+=(-cert ${C_CLNT_CERT[$j]})
            options+=(-connect localhost:4433)
            if [[ $prot == tls1_1 ]]; then
                options+=(-tls1_1)
            else
                options+=(-tls1_2)
            fi
            rlRun -s "expect openssl-client.expect ${options[*]}"
            rlAssertGrep "client hello" $rlRun_LOG
            rlRun "[[ $(grep 'client hello' $rlRun_LOG | wc -l) -eq 2 ]]" 0 \
                "Check if server echo'ed back our message"
            if [[ $prot == tls1_1 ]]; then
                rlAssertGrep "Protocol  : TLSv1.1" $rlRun_LOG
            else
                rlAssertGrep "Protocol  : TLSv1.2" $rlRun_LOG
            fi
            rlAssertGrep "CN=John Smith" server.log
            rlRun "kill $gnutls_pid"
            if ! rlGetPhaseState; then
                rlRun "cat server.log" 0 "Server stdout"
                rlRun "cat server.err" 0 "Server stderr"
            fi
            rlRun "rlWaitForSocket 4433 --close"
        rlPhaseEnd
      done
    done


    rlPhaseStartCleanup
        if ! rlIsRHEL '<8'; then
            if [[ $fips -ne 0 ]] || ! rlIsRHEL '<9'; then
                rlRun "rlFileRestore"
                rlRun "update-crypto-policies --set $current_policy"
            fi
        fi
        rlRun "popd"
        rlRun "rm -r $TmpDir" 0 "Removing tmp directory"
    rlPhaseEnd
rlJournalPrintText
rlJournalEnd
