#!/bin/bash
# vim: dict+=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   lib.sh of /CoreOS/gnutls/Library/tls-1-3-interoperability-gnutls-nss
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
#   library-prefix = tls13interop_gnutls_nss
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# Remember the library directory so that we'll know where to find .expect files
export tls13interop_gnutls_nss_EXPECTS=$(realpath $(dirname $BASH_SOURCE))

function tls13interop_gnutls_nssLibraryLoaded {( set -uex
    pushd /
    [[ -x $tls13interop_gnutls_nss_EXPECTS/gnutls-client.expect ]]
    [[ -x $tls13interop_gnutls_nss_EXPECTS/gnutls-resume.expect ]]
    [[ -x $tls13interop_gnutls_nss_EXPECTS/openssl-client.expect ]]
    [[ -x $tls13interop_gnutls_nss_EXPECTS/openssl-rekey.expect ]]
    popd
    return 0
)}

tls13interop_gnutls_nss_CIPHER_NAMES=()
tls13interop_gnutls_nss_CIPHER_NAMES+=('TLS_AES_128_GCM_SHA256')
tls13interop_gnutls_nss_CIPHER_NAMES+=('TLS_AES_256_GCM_SHA384')
tls13interop_gnutls_nss_CIPHER_NAMES+=('TLS_CHACHA20_POLY1305_SHA256')
# unsupported by NSS 3.38.0
#tls13interop_gnutls_nss_CIPHER_NAMES+=('TLS_AES_128_CCM_SHA256')
# unsupported by NSS (source: hkario)
#tls13interop_gnutls_nss_CIPHER_NAMES+=('TLS_AES_128_CCM_8_SHA256')

tls13interop_gnutls_nss_cipher_info() { local c_name=$1
    case $c_name in
    TLS_AES_128_GCM_SHA256)
        C_GNUTLS='TLS_AES_128_GCM_SHA256'
        C_OPENSSL='TLS_AES_128_GCM_SHA256'
        C_ID='1301'
    ;;
    TLS_AES_256_GCM_SHA384)
        C_GNUTLS='TLS_AES_256_GCM_SHA384'
        C_OPENSSL='TLS_AES_256_GCM_SHA384'
        C_ID='1302'
    ;;
    TLS_CHACHA20_POLY1305_SHA256)
        C_GNUTLS='TLS_CHACHA20_POLY1305_SHA256'
        C_OPENSSL='TLS_CHACHA20_POLY1305_SHA256'
        C_ID='1303'
    ;;
    # unsupported by NSS 3.38.0
    #TLS_AES_128_CCM_SHA256)
    #    C_GNUTLS='TLS_AES_128_CCM_SHA256'
    #    C_OPENSSL='TLS_AES_128_CCM_SHA256'
    #    C_ID='1304'
    #;;
    #TLS_AES_128_CCM_8_SHA256)
    #    C_GNUTLS='TLS_AES_128_CCM_8_SHA256'
    #    C_OPENSSL='TLS_AES_128_CCM_8_SHA256'
    #    C_ID='1305'
    #;;
    *) rlDie "Unknown cipher name $c_name";;
    esac
    echo $C_GNUTLS $C_OPENSSL $C_ID
}


tls13interop_gnutls_nss_GROUP_NAMES=()
tls13interop_gnutls_nss_GROUP_NAMES+=('default')
tls13interop_gnutls_nss_GROUP_NAMES+=('P-256')
tls13interop_gnutls_nss_GROUP_NAMES+=('P-384')
tls13interop_gnutls_nss_GROUP_NAMES+=('P-521')
tls13interop_gnutls_nss_GROUP_NAMES+=('X25519')
# X448 is not supported by NSS
tls13interop_gnutls_nss_GROUP_NAMES+=('FFDHE2048')
tls13interop_gnutls_nss_GROUP_NAMES+=('FFDHE3072')
tls13interop_gnutls_nss_GROUP_NAMES+=('FFDHE4096')
tls13interop_gnutls_nss_GROUP_NAMES+=('FFDHE6144')
tls13interop_gnutls_nss_GROUP_NAMES+=('FFDHE8192')

tls13interop_gnutls_nss_group_info() { local g_name=$1
    case $g_name in
    default)
        G_GNUTLS=''
        G_NSS=''
        G_GNUTLS_HRR=''
        G_NSS_HRR=''
        ;;
    P-256)
        G_GNUTLS=':-GROUP-ALL:+GROUP-SECP256R1'
        G_NSS='P256'
        G_GNUTLS_HRR=':-GROUP-ALL:+GROUP-SECP384R1:+GROUP-SECP256R1'
        G_NSS_HRR='P384,P256'
    ;;
    P-384)
        G_GNUTLS=':-GROUP-ALL:+GROUP-SECP384R1'
        G_NSS='P384'
        G_GNUTLS_HRR=':-GROUP-ALL:+GROUP-SECP256R1:+GROUP-SECP384R1'
        G_NSS_HRR='P256,P384'
    ;;
    P-521)
        G_GNUTLS=':-GROUP-ALL:+GROUP-SECP521R1'
        G_NSS='P521'
        G_GNUTLS_HRR=':-GROUP-ALL:+GROUP-SECP256R1:+GROUP-SECP521R1'
        G_NSS_HRR='P256,P521'
    ;;
    X25519)
        G_GNUTLS=':-GROUP-ALL:+GROUP-X25519'
        G_NSS='x25519'
        G_GNUTLS_HRR=':-GROUP-ALL:+GROUP-SECP256R1:+GROUP-X25519'
        G_NSS_HRR='P256,x25519'
    ;;
    #X448)
        # not supported by NSS
    #;;
    FFDHE2048)
        G_GNUTLS=':-GROUP-ALL:+GROUP-FFDHE2048'
        G_NSS='FF2048'
        G_GNUTLS_HRR=':-GROUP-ALL:+GROUP-FFDHE3072:+GROUP-FFDHE2048'
        G_NSS_HRR='P256,FF2048'
    ;;
    FFDHE3072)
        G_GNUTLS=':-GROUP-ALL:+GROUP-FFDHE3072'
        G_NSS='FF3072'
        G_GNUTLS_HRR=':-GROUP-ALL:+GROUP-FFDHE2048:+GROUP-FFDHE3072'
        G_NSS_HRR='P256,FF3072'
    ;;
    FFDHE4096)
        G_GNUTLS=':-GROUP-ALL:+GROUP-FFDHE4096'
        G_NSS='FF4096'
        G_GNUTLS_HRR=':-GROUP-ALL:+GROUP-FFDHE8192:+GROUP-FFDHE4096'
        G_NSS_HRR='FF2048,FF4096'
    ;;
    FFDHE6144)
        G_GNUTLS=':-GROUP-ALL:+GROUP-FFDHE6144'
        G_NSS='FF6144'
        G_GNUTLS_HRR=':-GROUP-ALL:+GROUP-FFDHE8192:+GROUP-FFDHE6144'
        G_NSS_HRR='FF2048,FF6144'
    ;;
    FFDHE8192)
        G_GNUTLS=':-GROUP-ALL:+GROUP-FFDHE8192'
        G_NSS='FF8192'
        G_GNUTLS_HRR=':-GROUP-ALL:+GROUP-FFDHE2048:+GROUP-FFDHE8192'
        G_NSS_HRR='P256,FF8192'
    ;;
    *) rlDie "Unknown group name $g_name";;
    esac
    echo $G_GNUTLS $G_NSS $G_GNUTLS_HRR $G_NSS_HRR
}


tls13interop_gnutls_nss_setup() {
    rlAssertRpm gnutls
    rlAssertRpm nss
    rlAssertRpm nss-tools
    rlAssertRpm openssl
    rlAssertRpm expect

    rlRun 'rlImport certgen'

    rlRun 'rlImport fips'
    fipsIsEnabled && FIPS=true || FIPS=false

    if rlIsRHEL '<8.1' && ! $FIPS; then
        # workaround BZ#1694603
        rlRun 'rlFileBackup /etc/crypto-policies/back-ends/nss.config'
        rlRun "sed -i 's/config=\"[^\"]*/&:CURVE25519/' /etc/crypto-policies/back-ends/nss.config"
        rlLog 'Updated nss crypto-policies backend to allow x25519'
    fi
    rlRun 'x509KeyGen ca'
    rlRun 'x509KeyGen rsa-ca'
    rlRun 'x509KeyGen -t rsa-pss rsa-pss-ca'
    rlRun 'x509KeyGen -t ecdsa -s prime256v1 ecdsa-p256-ca'
    rlRun 'x509KeyGen -t ecdsa -s secp384r1 ecdsa-p384-ca'
    rlRun 'x509KeyGen -t ecdsa -s secp521r1 ecdsa-p521-ca'
    rlRun 'x509KeyGen rsa-server'
    rlRun 'x509KeyGen -t rsa-pss rsa-pss-server'
    rlRun 'x509KeyGen -t ecdsa -s prime256v1 ecdsa-p256-server'
    rlRun 'x509KeyGen -t ecdsa -s secp384r1 ecdsa-p384-server'
    rlRun 'x509KeyGen -t ecdsa -s secp521r1 ecdsa-p521-server'
    rlRun 'x509KeyGen rsa-client'
    rlRun 'x509KeyGen -t rsa-pss rsa-pss-client'
    rlRun 'x509KeyGen -t ecdsa -s prime256v1 ecdsa-p256-client'
    rlRun 'x509KeyGen -t ecdsa -s secp384r1 ecdsa-p384-client'
    rlRun 'x509KeyGen -t ecdsa -s secp521r1 ecdsa-p521-client'
    rlRun 'x509SelfSign ca'
    rlRun 'x509CertSign --CA ca -t ca --DN "CN=RSA CA" rsa-ca'
    rlRun 'x509CertSign --CA ca -t ca --DN "CN=RSA-PSS CA" rsa-pss-ca'
    rlRun 'x509CertSign --CA ca -t ca --DN "CN=P-256 ECDSA CA" ecdsa-p256-ca'
    rlRun 'x509CertSign --CA ca -t ca --DN "CN=P-384 ECDSA CA" ecdsa-p384-ca'
    rlRun 'x509CertSign --CA ca -t ca --DN "CN=P-521 ECDSA CA" ecdsa-p521-ca'
    rlRun 'x509CertSign --CA rsa-ca rsa-server'
    rlRun 'x509CertSign --CA rsa-pss-ca rsa-pss-server'
    rlRun 'x509CertSign --CA ecdsa-p256-ca ecdsa-p256-server'
    rlRun 'x509CertSign --CA ecdsa-p384-ca ecdsa-p384-server'
    rlRun 'x509CertSign --CA ecdsa-p521-ca ecdsa-p521-server'
    rlRun 'x509CertSign --CA rsa-ca -t webclient rsa-client'
    rlRun 'x509CertSign --CA rsa-pss-ca -t webclient rsa-pss-client'
    rlRun 'x509CertSign --CA ecdsa-p256-ca -t webclient ecdsa-p256-client'
    rlRun 'x509CertSign --CA ecdsa-p384-ca -t webclient ecdsa-p384-client'
    rlRun 'x509CertSign --CA ecdsa-p521-ca -t webclient ecdsa-p521-client'
    rlRun 'x509DumpCert ca' 0 'Root CA'
    rlRun 'x509DumpCert rsa-ca' 0 'Intermediate RSA CA'
    rlRun 'x509DumpCert rsa-pss-ca' 0 'Intermediate RSA-PSS CA'
    rlRun 'x509DumpCert ecdsa-p256-ca' 0 'Intermediate ECDSA CA'
    rlRun 'x509DumpCert ecdsa-p384-ca' 0 'Intermediate ECDSA CA'
    rlRun 'x509DumpCert ecdsa-p521-ca' 0 'Intermediate ECDSA CA'
    rlRun 'x509DumpCert rsa-server' 0 'Server RSA certificate'
    rlRun 'x509DumpCert rsa-pss-server' 0 'Server RSA-PSS certificate'
    rlRun 'x509DumpCert ecdsa-p256-server' 0 'Server ECDSA certificate'
    rlRun 'x509DumpCert ecdsa-p384-server' 0 'Server ECDSA certificate'
    rlRun 'x509DumpCert ecdsa-p521-server' 0 'Server ECDSA certificate'
    rlRun 'x509DumpCert rsa-client' 0 'Client RSA certificate'
    rlRun 'x509DumpCert rsa-pss-client' 0 'Client RSA-PSS certificate'
    rlRun 'x509DumpCert ecdsa-p256-client' 0 'Client ECDSA certificate'
    rlRun 'x509DumpCert ecdsa-p384-client' 0 'Client ECDSA certificate'
    rlRun 'x509DumpCert ecdsa-p521-client' 0 'Client ECDSA certificate'

    rlRun 'mkdir ca-db' \
        0 'Create a directory with just a CA certificate'
    rlRun 'certutil -N --empty-password -d sql:./ca-db' \
        0 'Create a database for CA cert'
    rlRun "certutil -A -d sql:./ca-db -n ca -t 'cC,,' -a -i $(x509Cert ca)" \
        0 'Import CA certificate'
}


tls13interop_gnutls_nss_test() {
    local cert=$1 c_name=$2 c_sig=$3
    local g_name=$4 g_type=$5 sess_type=$6 k_update=$7
    rlGetPhaseState
    local START_ECODE=$ECODE


    if [[ $g_type == ' HRR' && $g_name == 'default' ]]; then
        rlDie 'Do not use HRR with default key exchange as by default all groups are enabled'
    fi

    if ! [[ $cert =~ rsa ]] && [[ $c_sig != 'default' ]]; then
        rlDie "cert $cert c_sig $c_sig invalid: for ECDSA, the hash is bound to the key type"
    fi

    if $FIPS && [[ $c_name = TLS_CHACHA20_POLY1305_SHA256 ]]; then
        rlDie "CHACHA20_POLY1305 is not allowed in FIPS mode"
    fi
    if $FIPS && [[ $g_name = X25519 ]]; then
        rlDie "X25519 is not allowed in FIPS mode"
    fi
    local GNUTLS_PRIO="NORMAL:+VERS-TLS1.3"
    local EXPECTS=$tls13interop_gnutls_nss_EXPECTS
    export SSLKEYLOGFILE='nss_log_file.txt'
    local SERVER_UTIL='/usr/lib/nss/unsupported-tools/selfserv'
    local CLIENT_UTIL='/usr/lib/nss/unsupported-tools/tstclnt'
    local STRSCLNT_UTIL='/usr/lib/nss/unsupported-tools/strsclnt'
    [ -f /usr/lib64/nss/unsupported-tools/selfserv ] && \
        SERVER_UTIL='/usr/lib64/nss/unsupported-tools/selfserv'
    [ -f /usr/lib64/nss/unsupported-tools/tstclnt ] && \
        CLIENT_UTIL='/usr/lib64/nss/unsupported-tools/tstclnt'
    [ -f /usr/lib64/nss/unsupported-tools/strsclnt ] && \
        STRSCLNT_UTIL='/usr/lib64/nss/unsupported-tools/strsclnt'

    local C_GNUTLS C_OPENSSL C_ID
    read C_GNUTLS C_OPENSSL C_ID \
       <<<$(tls13interop_gnutls_nss_cipher_info $c_name)

    local G_GNUTLS G_NSS G_GNUTLS_HRR G_NSS_HRR
    read G_GNUTLS G_NSS G_GNUTLS_HRR G_NSS_HRR \
       <<<$(tls13interop_gnutls_nss_group_info $g_name)

    if [[ $c_sig != 'default' ]]; then
        GNUTLS_SIG=":-SIGN-ALL:+SIGN-RSA-PSS-RSAE-$c_sig:+SIGN-RSA-PSS-$c_sig"
    else
        GNUTLS_SIG=''
    fi

    # NSS tools can't request or send KeyUpdate
    if [[ $k_update != ' key update' ]]; then

        if [[ $tls13interop_no_phases ]]; then
            rlLogInfo "::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::"
            rlLogInfo "::  GnuTLS server NSS client $c_name cipher $cert cert $c_sig sig_alg $g_name kex$g_type$sess_type$k_update"
            rlLogInfo "::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::"
        else
            rlPhaseStartTest "GnuTLS server NSS client $c_name cipher $cert cert $c_sig sig_alg $g_name kex$g_type$sess_type$k_update"
        fi
            [[ $DEBUG ]] && rlRun 'tcpdump -i lo -B 1024 -s 0 -U -w capture.pcap port 4433 &'
            [[ $DEBUG ]] && tcpdump_pid=$!
            [[ $DEBUG ]] && sleep 1.5 &
            [[ $DEBUG ]] && sleep_pid=$!
            options=(gnutls-serv)
            options+=(--http)
            options+=(-p 4433)
            options+=(--x509keyfile $(x509Key ${cert}-server))
            options+=(--x509certfile '<(cat $(x509Cert ${cert}-server) $(x509Cert ${cert}-ca))')
            options+=(--priority $GNUTLS_PRIO$GNUTLS_SIG$G_GNUTLS)
            options+=('>server.log' '2>server.err')
            rlRun "${options[*]} &"
            gnutls_pid=$!
            rlRun "rlWaitForSocket 4433 -d 0.1 -p $gnutls_pid"
            [[ $DEBUG ]] && rlRun "rlWaitForFile capture.pcap -d 0.1 -p $tcpdump_pid"
            if [[ $sess_type == ' resume' ]]; then
                options=($STRSCLNT_UTIL)
                options+=(-c 10 -P 20)
                options+=(-p 4433)
                options+=(-C :${C_ID})
            else
                options=($CLIENT_UTIL)
                options+=(-h localhost -p 4433)
                options+=(-c :${C_ID})
            fi
            if [[ $cert == rsa-pss ]]; then
                options+=(-J rsa_pss_pss_sha256,rsa_pss_pss_sha384,rsa_pss_pss_sha512)
            fi
            options+=(-d sql:./ca-db/)
            options+=(-V tls1.3:tls1.3)
            if [[ $sess_type == ' resume' ]]; then
                options+=(localhost)
            else
                # strsclnt does not support the -I option
                if [[ $g_type == ' HRR' ]]; then
                    options+=(-I $G_NSS_HRR)
                elif [[ $G_NSS ]]; then
                    options+=(-I $G_NSS)
                fi
            fi

            if [[ $sess_type == ' resume' ]]; then
                rlRun "${options[*]} &> client.log" 1
            else
                rlRun "expect $EXPECTS/nss-client.expect ${options[*]} \
                       &> client.log"
            fi

            if [[ $sess_type == ' resume' ]]; then
                # waiving bug 1731182
                # normally it should be "8 cache hits" and "8 stateless resumes"
                rlAssertGrep '[12345678] cache hits' 'client.log' -E
                rlAssertGrep '[12345678] stateless resumes' 'client.log' -E
            else
                # rlAssertGrep 'GET / HTTP/1.0' client.log  # can get torn apart
                rlAssertGrep 'HTTP/1.0 200 OK' client.log
            fi
            rlRun "kill $gnutls_pid"
            rlRun "rlWait -s 9 $gnutls_pid" 1
            [[ $DEBUG ]] && rlRun "rlWait -s 9 $sleep_pid"
            [[ $DEBUG ]] && rlRun "kill $tcpdump_pid"
            [[ $DEBUG ]] && rlRun "rlWait -s 9 $tcpdump_pid"
            rlGetPhaseState
            if [[ $ECODE -gt $START_ECODE ]]; then
                rlRun 'cat server.log' 0 'Server stdout'
                rlRun 'cat server.err' 0 'Server stderr'
                rlRun 'cat client.log' 0 'Client output'
                [[ $DEBUG == 'shell' ]] && bash
            fi
        if [[ $tls13interop_no_phases ]]; then
            rlLogInfo "::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::"
            rlLogInfo ""
        else
            rlPhaseEnd
        fi
    fi

    if [[ $tls13interop_no_phases ]]; then
        rlLogInfo "::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::"
        rlLogInfo "::  NSS server GnuTLS client $c_name cipher $cert cert $c_sig sig_alg $g_name kex$g_type$sess_type$k_update"
        rlLogInfo "::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::"
    else
        rlPhaseStartTest "NSS server GnuTLS client $c_name cipher $cert cert $c_sig sig_alg $g_name kex$g_type$sess_type$k_update"
    fi
        rlLogInfo 'Preparing NSS database'
        rlRun 'mkdir nssdb/'
        rlRun 'certutil -N --empty-password -d sql:./nssdb/'
        rlRun "certutil -A -d sql:./nssdb/ -n ca -t 'cC,,' -a -i $(x509Cert ca)"
        rlRun "certutil -A -d sql:./nssdb/ -n subca -t ',,' -a -i $(x509Cert ${cert}-ca)"
        rlRun "pk12util -i $(x509Key --pkcs12 --with-cert ${cert}-server) -d sql:./nssdb -W ''"

        rlLogInfo 'Test proper'
        [[ $DEBUG ]] && rlRun 'tcpdump -i lo -B 1024 -s 0 -U -w capture.pcap port 4433 &'
        [[ $DEBUG ]] && tcpdump_pid=$!
        [[ $DEBUG ]] && sleep 1.5 &
        [[ $DEBUG ]] && sleep_pid=$!
        declare -a options=()
        options+=(${SERVER_UTIL} -d sql:./nssdb/ -p 4433
                  -c :${C_ID} -H 1 -v)
        options+=(-V tls1.3:tls1.3)
        if [[ $G_NSS ]]; then
            options+=(-I $G_NSS)
        fi
        if [[ $sess_type == ' resume' ]]; then
            options+=(-u)
        fi

        # ecdsa certs require different option to specify used key
        if [[ $cert =~ 'ecdsa' ]]; then
            options+=(-e $cert-server)
        else
            options+=(-n $cert-server)
        fi
        if [[ $cert = 'rsa-pss' ]]; then
            options+=(-J rsa_pss_pss_sha256,rsa_pss_pss_sha384,rsa_pss_pss_sha512)
        fi
        rlRun "expect $EXPECTS/nss-server.expect ${options[*]} \
               >server.log 2>server.err &"
        nss_pid=$!
        rlRun "rlWaitForSocket -d 0.1 4433 -p $nss_pid"
        [[ $DEBUG ]] && rlRun "rlWaitForFile -d 0.1 -p $tcpdump_pid capture.pcap"

        options=(gnutls-cli)
        options+=(--x509cafile $(x509Cert ca))
        options+=(-p 4433 localhost)
        if [[ $k_update == ' key update' ]]; then
            options+=(--inline-commands)
        fi
        if [[ $g_type == ' HRR' ]]; then
            options+=(--priority $GNUTLS_PRIO$GNUTLS_SIG$G_GNUTLS_HRR)
            options+=(--single-key-share)
        else
            options+=(--priority $GNUTLS_PRIO$GNUTLS_SIG$G_GNUTLS)
        fi
        if [[ $sess_type == ' resume' ]]; then
            # On RHEL 8.3, --waitresumption option was added to gnutls-cli (#1677754)
            if rlIsRHEL '<8.3'; then
                options+=(--resume)
            else
                options+=(--resume --waitresumption)
            fi
        fi

        if [[ $sess_type == ' resume' ]]; then
            rlRun "expect $EXPECTS/gnutls-resume.expect  ${options[*]} \
                   &> client.log"
        else
            rlRun "expect $EXPECTS/gnutls-client.expect ${options[*]} \
                   &> client.log"
        fi

        rlAssertGrep 'GET / HTTP/1.0' client.log
        rlAssertGrep 'Server: Generic Web Server' client.log
        if [[ $sess_type == ' resume' ]]; then
            rlAssertGrep 'Resume Handshake was completed' client.log
            rlAssertGrep 'This is a resumed session' client.log
        fi
        rlRun "kill $nss_pid"
        rlRun "rlWait -s 9 $nss_pid" 0
        [[ $DEBUG ]] && rlRun "rlWait -s 9 $sleep_pid"
        [[ $DEBUG ]] && rlRun "kill $tcpdump_pid"
        [[ $DEBUG ]] && rlRun "rlWait -s 9 $tcpdump_pid"
        rlGetPhaseState
        if [[ $ECODE -gt $START_ECODE ]]; then
            rlRun 'cat server.log' 0 'Server stdout'
            rlRun 'cat server.err' 0 'Server stderr'
            rlRun 'cat client.log' 0 'Client output'
            [[ $DEBUG == 'shell' ]] && bash
        fi
        rlRun 'rm -rf nssdb/' 0 'Clean up NSS database'
    if [[ $tls13interop_no_phases ]]; then
        rlLogInfo "::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::"
        rlLogInfo ""
    else
        rlPhaseEnd
    fi

    # NSS tools can't request or send KeyUpdate
    if [[ $k_update != ' key update' ]]; then

        # strsclnt doesn't support setting supported sigalgs
        if [[ $tls13interop_no_phases ]]; then
            rlLogInfo "::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::"
            rlLogInfo "::  GnuTLS server NSS client $c_name cipher $cert client cert $c_sig sig_alg $g_name kex$g_type$sess_type$k_update"
            rlLogInfo "::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::"
        else
            rlPhaseStartTest "GnuTLS server NSS client $c_name cipher $cert client cert $c_sig sig_alg $g_name kex$g_type$sess_type$k_update"
        fi
            rlLogInfo 'Prepare nss db for client'
            rlRun 'mkdir nssdb/'
            rlRun 'certutil -N --empty-password -d sql:./nssdb'
            rlRun "certutil -A -d sql:./nssdb -n ca -t 'cCT,,' -a -i $(x509Cert ca)"
            rlRun "certutil -A -d sql:./nssdb -n subca -t ',,' -a -i $(x509Cert ${cert}-ca)"
            rlRun "pk12util -i $(x509Key --pkcs12 --with-cert ${cert}-client) -d sql:./nssdb -W ''" \
                0 'Import client certificate'
            rlRun 'certutil -L -d sql:./nssdb'

            rlLogInfo 'Test proper'
            [[ $DEBUG ]] && rlRun 'tcpdump -i lo -B 1024 -s 0 -U -w capture.pcap port 4433 &'
            [[ $DEBUG ]] && tcpdump_pid=$!
            [[ $DEBUG ]] && sleep 1.5 &
            [[ $DEBUG ]] && sleep_pid=$!
            options=(--http -p 4433)
            options+=(--x509keyfile $(x509Key $cert-server))
            options+=(--x509certfile '<(cat $(x509Cert ${cert}-server) $(x509Cert ${cert}-ca))')
            options+=(--x509cafile '<(cat $(x509Cert ca) $(x509Cert ${cert}-ca))')
            options+=(--priority $GNUTLS_PRIO$GNUTLS_SIG$G_GNUTLS)
            options+=(--require-client-cert --verify-client-cert)
            rlRun "gnutls-serv ${options[*]} >server.log 2>server.err &"
            gnutls_pid=$!
            rlRun "rlWaitForSocket -d 0.1 4433 -p $gnutls_pid"

            [[ $DEBUG ]] && rlRun "rlWaitForFile -d 0.1 -p $tcpdump_pid capture.pcap"
            if [[ $sess_type == ' resume' ]]; then
                options=(${STRSCLNT_UTIL})
                options+=(-c 10 -P 20)
                options+=(-p 4433)
                options+=(-C :${C_ID})
            else
                options=(${CLIENT_UTIL})
                options+=(-h localhost -p 4433)
                options+=(-c :${C_ID})
            fi
            if [[ $cert == rsa-pss ]]; then
                options+=(-J rsa_pss_pss_sha256,rsa_pss_pss_sha384,rsa_pss_pss_sha512)
            fi
            options+=(-d sql:./nssdb/)
            options+=(-n ${cert}-client)
            options+=(-V tls1.3:tls1.3)
            if [[ $sess_type == ' resume' ]]; then
                options+=(localhost)
            else
                # strsclnt doesn't support -I option
                if [[ $g_type == ' HRR' ]]; then
                    options+=(-I $G_NSS_HRR)
                elif [[ $G_NSS ]]; then
                    options+=(-I $G_NSS)
                fi
            fi

            if [[ $sess_type == ' resume' ]]; then
                rlRun "${options[*]} &> client.log" 1
            else
                rlRun "expect $EXPECTS/nss-client.expect ${options[*]} \
                       &> client.log"
            fi

            if [[ $sess_type == ' resume' ]]; then
                # waiving bug 1731182
                # normally it should be "8 cache hits" and "8 stateless resumes"
                rlAssertGrep '[12345678] cache hits' 'client.log' -E
                rlAssertGrep '[12345678] stateless resumes' 'client.log' -E
            else
                # rlAssertGrep 'GET / HTTP/1.0' client.log  # can get torn apart
                rlAssertGrep 'HTTP/1.0 200 OK' client.log
            fi
            rlRun "kill $gnutls_pid"
            rlRun "rlWait -s 9 $gnutls_pid" 1
            [[ $DEBUG ]] && rlRun "rlWait -s 9 $sleep_pid"
            [[ $DEBUG ]] && rlRun "kill $tcpdump_pid"
            [[ $DEBUG ]] && rlRun "rlWait -s 9 $tcpdump_pid"
            rlGetPhaseState
            if [[ $ECODE -gt $START_ECODE ]]; then
                rlRun 'cat server.log' 0 'Server stdout'
                rlRun 'cat server.err' 0 'Server stderr'
                rlRun 'cat client.log' 0 'Client output'
                [[ $DEBUG == 'shell' ]] && bash
            fi
            rlRun 'rm -rf nssdb'
        if [[ $tls13interop_no_phases ]]; then
            rlLogInfo "::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::"
            rlLogInfo ""
        else
            rlPhaseEnd
        fi
    fi

    if [[ $tls13interop_no_phases ]]; then
        rlLogInfo "::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::"
        rlLogInfo "::  NSS server GnuTLS client $c_name cipher $cert client cert $c_sig sig_alg $g_name kex$g_type$sess_type$k_update"
        rlLogInfo "::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::"
    else
        rlPhaseStartTest "NSS server GnuTLS client $c_name cipher $cert client cert $c_sig sig_alg $g_name kex$g_type$sess_type$k_update"
    fi
        [[ $DEBUG ]] && rlRun 'tcpdump -i lo -B 1024 -s 0 -U -w capture.pcap port 4433 &'
        [[ $DEBUG ]] && tcpdump_pid=$!
        [[ $DEBUG ]] && sleep 1.5 &
        [[ $DEBUG ]] && sleep_pid=$!
        rlLogInfo 'Preparing NSS database'
        rlRun 'mkdir nssdb/'
        rlRun 'certutil -N --empty-password -d sql:./nssdb/'
        rlRun "certutil -A -d sql:./nssdb/ -n ca -t 'cCT,,' -a -i $(x509Cert ca)"
        rlRun "certutil -A -d sql:./nssdb/ -n subca -t ',,' -a -i $(x509Cert ${cert}-ca)"
        rlRun "pk12util -i $(x509Key --pkcs12 --with-cert ${cert}-server) -d sql:./nssdb -W ''"

        rlLogInfo 'Test proper'
        declare -a options=()
        options+=(${SERVER_UTIL})
        options+=(-d sql:./nssdb/)
        options+=(-p 4433)
        options+=(-c :${C_ID} -H 1)
        options+=(-rr)
        options+=(-v)
        options+=(-V tls1.3:tls1.3)
        if [[ $G_NSS ]]; then
            options+=(-I $G_NSS)
        fi
        if [[ $sess_type == ' resume' ]]; then
            options+=(-u)
        fi

        # ecdsa certs require different option to specify used key
        if [[ ${cert} =~ 'ecdsa' ]]; then
            options+=(-e ${cert}-server)
        else
            options+=(-n ${cert}-server)
        fi
        if [[ ${cert} == 'rsa-pss' ]]; then
            options+=(-J rsa_pss_pss_sha256,rsa_pss_pss_sha384,rsa_pss_pss_sha512)
        fi
        rlRun "expect $EXPECTS/nss-server.expect \
                   ${options[*]} >server.log 2>server.err &"
        nss_pid=$!
        rlRun "rlWaitForSocket -d 0.1 4433 -p $nss_pid"
        [[ $DEBUG ]] && rlRun "rlWaitForFile -d 0.1 -p $tcpdump_pid capture.pcap"
        options=(gnutls-cli)
        options+=(--x509cafile '<(cat $(x509Cert ca) $(x509Cert ${cert}-ca))')
        options+=(-p 4433 localhost)
        options+=(--x509certfile $(x509Cert ${cert}-client))
        options+=(--x509keyfile $(x509Key ${cert}-client))
        if [[ $g_type == ' HRR' ]]; then
            options+=(--priority $GNUTLS_PRIO$GNUTLS_SIG$G_GNUTLS_HRR)
            options+=(--single-key-share)
        else
            options+=(--priority $GNUTLS_PRIO$GNUTLS_SIG$G_GNUTLS)
        fi
        if [[ $sess_type == ' resume' ]]; then
            # On RHEL 8.3, --waitresumption option was added to gnutls-cli (#1677754)
            if rlIsRHEL '<8.3'; then
                options+=(--resume)
            else
                options+=(--resume --waitresumption)
            fi
        fi
        if [[ $k_update == ' key update' ]]; then
            options+=(--inline-commands)
        fi

        if [[ $sess_type == ' resume' ]]; then
            rlRun "expect $EXPECTS/gnutls-resume.expect \
                       ${options[*]} &> client.log"
        else
            rlRun "expect $EXPECTS/gnutls-client.expect \
                       ${options[*]} &> client.log"
        fi

        rlAssertGrep 'GET / HTTP/1.0' client.log
        rlAssertGrep 'Server: Generic Web Server' client.log
        if [[ $sess_type == ' resume' ]]; then
            rlAssertGrep 'Resume Handshake was completed' client.log
            rlAssertGrep 'This is a resumed session' client.log
        fi
        rlRun "kill $nss_pid"
        rlRun "rlWait -s 9 $nss_pid" 0
        [[ $DEBUG ]] && rlRun "rlWait -s 9 $sleep_pid"
        [[ $DEBUG ]] && rlRun "kill $tcpdump_pid"
        [[ $DEBUG ]] && rlRun "rlWait -s 9 $tcpdump_pid"
        rlGetPhaseState
        if [[ $ECODE -gt $START_ECODE ]]; then
            rlRun 'cat server.log' 0 'Server stdout'
            rlRun 'cat server.err' 0 'Server stderr'
            rlRun 'cat client.log' 0 'Client output'
            [[ $DEBUG == 'shell' ]] && bash
        fi
        rlRun 'rm -rf nssdb/' 0 'Clean up NSS database'
    if [[ $tls13interop_no_phases ]]; then
        rlLogInfo "::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::"
        rlLogInfo ""
    else
        rlPhaseEnd
    fi

    unset SSLKEYLOGFILE
}


tls13interop_gnutls_nss_cleanup() {
    if rlIsRHEL '<8.1' && ! $FIPS; then
        rlRun 'rlFileRestore'
    fi
}

tls13interop_gnutls_nss_test_all_for_cert() { local cert=$1
    for c_name in "${tls13interop_gnutls_nss_CIPHER_NAMES[@]}"; do
     for c_sig in 'default' 'SHA256' 'SHA384' 'SHA512'; do
      for g_name in "${tls13interop_gnutls_nss_GROUP_NAMES[@]}"; do
       for g_type in '' ' HRR'; do
        for sess_type in '' ' resume'; do
         for k_update in '' ' key update'; do

          # skip HRR for default key exchange
          # as by default all groups are enabled
          if [[ $g_type == ' HRR' && $g_name == 'default' ]]; then
              continue
          fi

          # for ECDSA, the hash is bound to the key type
          if ! [[ $cert =~ rsa ]] && [[ $c_sig != 'default' ]]; then
              continue
          fi

          # CHACHA20_POLY1305 and X25519 are not allowed in FIPS mode
          if $FIPS && [[ $c_name = TLS_CHACHA20_POLY1305_SHA256 ]]; then
              continue;
          fi
          if $FIPS && [[ $g_name = X25519 ]]; then
              continue
          fi

          tls13interop_gnutls_nss_test \
              "$cert" "$c_name" "$c_sig" "$g_name" \
              "$g_type" "$sess_type" "$k_update"

         done  # k_update
        done  # sess_type
       done  # g_type
      done  # g_name
     done  # c_sig
    done  # c_name
}


tls13interop_gnutls_nss_test_all() {
    for cert in 'rsa' 'rsa-pss' 'ecdsa-p256' 'ecdsa-p384' 'ecdsa-p521'; do
        tls13interop_gnutls_nss_test_all_for_cert $cert
    done
}
