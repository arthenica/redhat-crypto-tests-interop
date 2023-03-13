#!/bin/bash
# vim: dict+=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   lib.sh of /CoreOS/openssl/Library/tls-1-3-interoperability-nss-openssl
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
#   library-prefix = tls13interop_nss_openssl
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# Remember the library directory so that we'll know where to find .expect files
export tls13interop_nss_openssl_EXPECTS=$(realpath $(dirname $BASH_SOURCE))


function tls13interop_nss_opensslLibraryLoaded {( set -uex
    pushd /
    [[ -x $tls13interop_nss_openssl_EXPECTS/nss-client.expect ]]
    [[ -x $tls13interop_nss_openssl_EXPECTS/nss-server.expect ]]
    [[ -x $tls13interop_nss_openssl_EXPECTS/openssl-client.expect ]]
    [[ -x $tls13interop_nss_openssl_EXPECTS/openssl-rekey.expect ]]
    popd
    return 0
)}


tls13interop_nss_openssl_CIPHER_NAMES=()
tls13interop_nss_openssl_CIPHER_NAMES+=('TLS_AES_128_GCM_SHA256')
tls13interop_nss_openssl_CIPHER_NAMES+=('TLS_AES_256_GCM_SHA384')
tls13interop_nss_openssl_CIPHER_NAMES+=('TLS_CHACHA20_POLY1305_SHA256')
# unsupported by NSS 3.38.0
#tls13interop_nss_openssl_CIPHER_NAMES+=('TLS_AES_128_CCM_SHA256')
# unsupported by NSS (source: hkario)
#tls13interop_nss_openssl_CIPHER_NAMES+=('TLS_AES_128_CCM_8_SHA256')

tls13interop_nss_openssl_cipher_info() { local c_name=$1
    case $c_name in
    TLS_AES_128_GCM_SHA256)
        C_OPENSSL='TLS_AES_128_GCM_SHA256'
        C_ID='1301'
    ;;
    TLS_AES_256_GCM_SHA384)
        C_OPENSSL='TLS_AES_256_GCM_SHA384'
        C_ID='1302'
    ;;
    TLS_CHACHA20_POLY1305_SHA256)
        C_OPENSSL='TLS_CHACHA20_POLY1305_SHA256'
        C_ID='1303'
    ;;
    #TLS_AES_128_CCM_SHA256)
    #    C_OPENSSL='TLS_AES_128_CCM_SHA256'
    #    C_ID='1304'
    #;;
    #TLS_AES_128_CCM_8_SHA256)
    #    C_OPENSSL='TLS_AES_128_CCM_8_SHA256'
    #    C_ID='1305'
    #;;
    *) rlDie "Unknown cipher name $c_name";;
    esac
    echo $C_OPENSSL $C_ID
}


tls13interop_nss_openssl_GROUP_NAMES=()
tls13interop_nss_openssl_GROUP_NAMES+=('default')
tls13interop_nss_openssl_GROUP_NAMES+=('P-256')
tls13interop_nss_openssl_GROUP_NAMES+=('P-384')
tls13interop_nss_openssl_GROUP_NAMES+=('P-521')
tls13interop_nss_openssl_GROUP_NAMES+=('X25519')
# X448 is not supported by NSS
if ! rlIsRHEL '<9'; then
    # FFDHE is not supported by OpenSSL 1.1.1 RHBZ#1593671
    # https://github.com/openssl/openssl/issues/6519
    # added in RHEL-9 with OpenSSL 3.0.0
    tls13interop_nss_openssl_GROUP_NAMES+=('FFDHE2048')
    tls13interop_nss_openssl_GROUP_NAMES+=('FFDHE3072')
    tls13interop_nss_openssl_GROUP_NAMES+=('FFDHE4096')
    tls13interop_nss_openssl_GROUP_NAMES+=('FFDHE6144')
    tls13interop_nss_openssl_GROUP_NAMES+=('FFDHE8192')
fi

tls13interop_nss_openssl_group_info() { local g_name=$1
    case $g_name in
    default)
        G_OPENSSL=''
        G_NSS=''
        G_OPENSSL_HRR=''
        G_NSS_HRR=''
        ;;
    P-256)
        G_OPENSSL='P-256'
        G_NSS='P256'
        G_OPENSSL_HRR='P-384:P-256'
        G_NSS_HRR='P384,P256'
    ;;
    P-384)
        G_OPENSSL='P-384'
        G_NSS='P384'
        G_OPENSSL_HRR='P-256:P-384'
        G_NSS_HRR='P256,P384'
    ;;
    P-521)
        G_OPENSSL='P-521'
        G_NSS='P521'
        G_OPENSSL_HRR='P-256:P-521'
        G_NSS_HRR='P256,P521'
    ;;
    X25519)
        G_OPENSSL='X25519'
        G_NSS='x25519'
        G_OPENSSL_HRR='P-256:X25519'
        G_NSS_HRR='P256,x25519'
    ;;
    #X448)
        # not supported by NSS
    #;;
    FFDHE2048)
        G_OPENSSL='ffdhe2048'
        G_NSS='FF2048'
        G_OPENSSL_HRR='P-256:ffdhe2048'
        G_NSS_HRR='P384,FF2048'
    ;;
    FFDHE3072)
        G_OPENSSL='ffdhe3072'
        G_NSS='FF3072'
        G_OPENSSL_HRR='ffdhe2048:ffdhe3072'
        G_NSS_HRR='FF4096,FF3072'
    ;;
    FFDHE4096)
        G_OPENSSL='ffdhe4096'
        G_NSS='FF4096'
        G_OPENSSL_HRR='ffdhe8192:ffdhe4096'
        G_NSS_HRR='FF6144,FF4096'
    ;;
    FFDHE6144)
        G_OPENSSL='ffdhe6144'
        G_NSS='FF6144'
        G_OPENSSL_HRR='ffdhe4096:ffdhe6144'
        G_NSS_HRR='FF8192,FF6144'
    ;;
    FFDHE8192)
        G_OPENSSL='ffdhe8192'
        G_NSS='FF8192'
        G_OPENSSL_HRR='ffdhe6144:ffdhe8192'
        G_NSS_HRR='FF4096,FF8192'
    ;;
    *) rlDie "Unknown group name $g_name";;
    esac
    echo $G_OPENSSL $G_NSS $G_OPENSSL_HRR $G_NSS_HRR
}


tls13interop_nss_openssl_setup() {
    rlAssertRpm expect
    rlAssertRpm nss
    rlAssertRpm nss-tools
    rlAssertRpm openssl

    rlRun 'rlImport certgen'

    rlRun 'rlImport fips'
    fipsIsEnabled && FIPS=true || FIPS=false

    if rlIsRHEL '<8.1' && ! $FIPS; then
        # workaround BZ#1694603
        local nss_pol='/etc/crypto-policies/back-ends/nss.config'
        rlRun "rlFileBackup $nss_pol"
        rlRun "sed -i 's/ allow=/ allow=CURVE25519:/' $nss_pol"
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
        0 'Create a database for the CA cert'
    rlRun "certutil -A -d sql:./ca-db -n ca -t 'cC,,' -a -i $(x509Cert ca)" \
        0 'Import CA certificate'
}


tls13interop_nss_openssl_test() {
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

    local EXPECTS=$tls13interop_nss_openssl_EXPECTS
    export SSLKEYLOGFILE=key_log_file.txt
    local SERVER_UTIL='/usr/lib/nss/unsupported-tools/selfserv'
    local CLIENT_UTIL='/usr/lib/nss/unsupported-tools/tstclnt'
    local STRSCLNT_UTIL='/usr/lib/nss/unsupported-tools/strsclnt'
    [ -f /usr/lib64/nss/unsupported-tools/selfserv ] && \
        SERVER_UTIL='/usr/lib64/nss/unsupported-tools/selfserv'
    [ -f /usr/lib64/nss/unsupported-tools/tstclnt ] && \
        CLIENT_UTIL='/usr/lib64/nss/unsupported-tools/tstclnt'
    [ -f /usr/lib64/nss/unsupported-tools/strsclnt ] && \
        STRSCLNT_UTIL='/usr/lib64/nss/unsupported-tools/strsclnt'

    local C_OPENSSL C_ID
    read C_OPENSSL C_ID \
        <<<$(tls13interop_nss_openssl_cipher_info $c_name)

    local G_OPENSSL G_NSS G_OPENSSL_HRR G_NSS_HRR
    read G_OPENSSL G_NSS G_OPENSSL_HRR G_NSS_HRR \
        <<<$(tls13interop_nss_openssl_group_info $g_name)

    if [[ $c_sig != 'default' ]]; then
        if [[ $cert == rsa ]]; then
            OPENSSL_SIG="rsa_pss_rsae_${c_sig,,}"
        else
            OPENSSL_SIG="rsa_pss_pss_${c_sig,,}"
        fi
    else
        OPENSSL_SIG=''
    fi

    # NSS tools can't request or send KeyUpdate
    if [[ $k_update != ' key update' ]]; then
        if [[ $tls13interop_no_phases ]]; then
            rlLogInfo "::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::"
            rlLogInfo "::  OpenSSL server NSS client $C_OPENSSL cipher $cert cert $c_sig sig_alg $g_name kex$g_type$sess_type$k_update"
            rlLogInfo "::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::"
        else
            rlPhaseStartTest "OpenSSL server NSS client $C_OPENSSL cipher $cert cert $c_sig sig_alg $g_name kex$g_type$sess_type$k_update"
        fi
            [[ $DEBUG ]] && rlRun 'tcpdump -i lo -B 1024 -s 0 -U -w capture.pcap port 4433 &'
            [[ $DEBUG ]] && tcpdump_pid=$!
            [[ $DEBUG ]] && sleep 1.5 &
            [[ $DEBUG ]] && sleep_pid=$!
            rlRun "openssl x509 -in $(x509Cert ca) -trustout -out trust.pem"
            rlRun "cat $(x509Cert $cert-ca) >> trust.pem"
            declare -a options=(openssl s_server -www)
            if [[ $G_OPENSSL ]]; then
                options+=(-groups $G_OPENSSL)
            fi
            if [[ -n $OPENSSL_SIG ]]; then
                options+=(-sigalgs $OPENSSL_SIG)
            fi
            options+=(-CAfile trust.pem)
            options+=(-build_chain)
            options+=(-cert $(x509Cert $cert-server))
            options+=(-key $(x509Key $cert-server))
            options+=(-keylogfile openssl_keylog.txt)
            options+=(-ciphersuites $C_OPENSSL)

            rlRun "${options[*]} >server.log 2>server.err &"
            openssl_pid=$!
            rlRun "rlWaitForSocket -d 0.1 4433 -p $openssl_pid"
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
                # waiving the bug 1731182, normally it should be
                # "8 cache hits" and "8 stateless resumes"
                rlAssertGrep '[12345678] cache hits' client.log -E
                rlAssertGrep '[12345678] stateless resumes' client.log -E
            else
                rlAssertGrep 'GET / HTTP/1.0' client.log
                rlAssertGrep 'HTTP/1.0 200 ok' client.log
                rlAssertGrep "$C_OPENSSL" client.log
            fi
            rlRun "kill $openssl_pid"
            rlRun "rlWait -s 9 $openssl_pid" 143
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
        rlLogInfo "::  NSS server OpenSSL client $C_OPENSSL cipher $cert cert $c_sig sig_alg $g_name kex$g_type$sess_type$k_update"
        rlLogInfo "::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::"
    else
        rlPhaseStartTest "NSS server OpenSSL client $C_OPENSSL cipher $cert cert $c_sig sig_alg $g_name kex$g_type$sess_type$k_update"
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
        options+=($SERVER_UTIL -d sql:./nssdb/ -p 4433
                  -c :${C_ID} -H 1)
        options+=(-V tls1.3:tls1.3)
        if [[ $G_NSS ]]; then
            options+=(-I $G_NSS)
        fi
        if [[ $sess_type == ' resume' ]]; then
            options+=(-u)
        fi
        if [[ $cert == rsa-pss ]]; then
            options+=(-J rsa_pss_pss_sha256,rsa_pss_pss_sha384,rsa_pss_pss_sha512)
        fi

        # ecdsa certs require different option to specify used key
        if [[ $cert =~ 'ecdsa' ]]; then
            options+=(-e $cert-server)
        else
            options+=(-n $cert-server)
        fi
        rlRun "expect $EXPECTS/nss-server.expect ${options[*]} >server.log 2>server.err &"
        nss_pid=$!
        rlRun "rlWaitForSocket -d 0.1 4433 -p $nss_pid"
        [[ $DEBUG ]] && rlRun "rlWaitForFile -d 0.1 -p $tcpdump_pid capture.pcap"

        options=(openssl s_client)
        if [[ $sess_type == ' resume' ]]; then
            options+=(-sess_out sess.pem)
        fi
        options+=(-CAfile $(x509Cert ca))
        options+=(-connect localhost:4433)
        options+=(-keylogfile openssl_keylog.txt)
        options+=(-ciphersuites $C_OPENSSL)
        if [[ -n $OPENSSL_SIG ]]; then
            options+=(-sigalgs $OPENSSL_SIG)
        fi
        if [[ $g_type == ' HRR' ]]; then
            options+=(-groups $G_OPENSSL_HRR)
        elif [[ $G_OPENSSL ]]; then
            options+=(-groups $G_OPENSSL)
        fi

        if [[ $k_update == ' key update' ]]; then
            rlRun "expect $EXPECTS/openssl-rekey.expect ${options[*]} \
                   &> client.log"
        else
            rlRun "expect $EXPECTS/openssl-client.expect ${options[*]} \
                   &> client.log"
        fi

        rlAssertGrep 'GET / HTTP/1.0' client.log
        rlAssertGrep 'Server: Generic Web Server' client.log
        rlAssertGrep "Cipher is $C_OPENSSL" client.log

        if [[ $sess_type == ' resume' ]]; then
            rlLogInfo 'Trying session resumption'
            options=(openssl s_client)
            options+=(-sess_in sess.pem)
            options+=(-CAfile $(x509Cert ca))
            options+=(-connect localhost:4433)
            options+=(-keylogfile openssl_keylog.txt)
            options+=(-ciphersuites $C_OPENSSL)
            if [[ -n $OPENSSL_SIG ]]; then
                options+=(-sigalgs $OPENSSL_SIG)
            fi
            if [[ $g_type == ' HRR' ]]; then
                options+=(-groups $G_OPENSSL_HRR)
            elif [[ $G_OPENSSL ]]; then
                options+=(-groups $G_OPENSSL)
            fi

            if [[ $k_update == ' key update' ]]; then
                rlRun "expect $EXPECTS/openssl-rekey.expect ${options[*]} &> client.log"
            else
                rlRun "expect $EXPECTS/openssl-client.expect ${options[*]} &> client.log"
            fi

            rlAssertGrep 'GET / HTTP/1.0' client.log
            rlAssertGrep 'HTTP/1.0 200 OK' client.log
            rlAssertGrep 'Reused, TLSv1.3' client.log

            rlLogInfo 'Second resume'
            options=(openssl s_client)
            options+=(-sess_in sess.pem)
            options+=(-CAfile $(x509Cert ca))
            options+=(-connect localhost:4433)
            options+=(-keylogfile openssl_keylog.txt)
            options+=(-ciphersuites $C_OPENSSL)
            if [[ -n $OPENSSL_SIG ]]; then
                options+=(-sigalgs $OPENSSL_SIG)
            fi
            if [[ $g_type == ' HRR' ]]; then
                options+=(-groups $G_OPENSSL_HRR)
            elif [[ $G_OPENSSL ]]; then
                options+=(-groups $G_OPENSSL)
            fi

            if [[ $k_update == ' key update' ]]; then
                rlRun "expect $EXPECTS/openssl-rekey.expect ${options[*]} \
                       &> client.log"
            else
                rlRun "expect $EXPECTS/openssl-client.expect ${options[*]} \
                       &> client.log"
            fi

            rlAssertGrep 'GET / HTTP/1.0' client.log
            rlAssertGrep 'HTTP/1.0 200 OK' client.log
            rlAssertGrep 'Reused, TLSv1.3' client.log
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
        if [[ $tls13interop_no_phases ]]; then
            rlLogInfo "::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::"
            rlLogInfo "::  OpenSSL server NSS client $C_OPENSSL cipher $cert client cert $c_sig sig_alg $g_name kex$g_type$sess_type$k_update"
            rlLogInfo "::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::"
        else
            rlPhaseStartTest "OpenSSL server NSS client $C_OPENSSL cipher $cert client cert $c_sig sig_alg $g_name kex$g_type$sess_type$k_update"
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
            rlRun "openssl x509 -in $(x509Cert ca) -trustout -out trust.pem"
            rlRun "cat $(x509Cert $cert-ca) >> trust.pem"
            declare -a options=(openssl s_server -www)
            options+=(-CAfile trust.pem)
            options+=(-build_chain)
            options+=(-cert $(x509Cert $cert-server))
            options+=(-key $(x509Key $cert-server))
            options+=(-ciphersuites $C_OPENSSL)
            options+=(-keylogfile openssl_keylog.txt)
            options+=(-ciphersuites $C_OPENSSL)
            if [[ -n $OPENSSL_SIG ]]; then
                options+=(-client_sigalgs $OPENSSL_SIG)
            fi
            options+=(-Verify 3)
            rlRun "${options[*]} >server.log 2>server.err &"
            openssl_pid=$!
            rlRun "rlWaitForSocket -d 0.1 4433 -p $openssl_pid"
            [[ $DEBUG ]] && rlRun "rlWaitForFile -d 0.1 -p $tcpdump_pid capture.pcap"
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
                # waiving the bug 1731182, normally it should be
                # "8 cache hits" and "8 stateless resumes"
                rlAssertGrep '[12345678] cache hits' client.log -E
                rlAssertGrep '[12345678] stateless resumes' client.log -E
            else
                rlAssertGrep 'GET / HTTP/1.0' client.log
                rlAssertGrep 'HTTP/1.0 200 ok' client.log
                rlAssertGrep "$C_OPENSSL" client.log
            fi
            rlRun "kill $openssl_pid"
            rlRun "rlWait -s 9 $openssl_pid" 143
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
        rlLogInfo "::  NSS server OpenSSL client $C_OPENSSL cipher $cert client cert $c_sig sig_alg $g_name kex$g_type$sess_type$k_update"
        rlLogInfo "::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::"
    else
        rlPhaseStartTest "NSS server OpenSSL client $C_OPENSSL cipher $cert client cert $c_sig sig_alg $g_name kex$g_type$sess_type$k_update"
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
        options+=($SERVER_UTIL)
        options+=(-d sql:./nssdb/)
        options+=(-p 4433)
        options+=(-c :${C_ID} -H 1)
        options+=(-rr)
        options+=(-V tls1.3:tls1.3)
        if [[ $G_NSS ]]; then
            options+=(-I $G_NSS)
        fi
        if [[ $sess_type == ' resume' ]]; then
            options+=(-u)
        fi
        if [[ $cert == rsa-pss ]]; then
            options+=(-J rsa_pss_pss_sha256,rsa_pss_pss_sha384,rsa_pss_pss_sha512)
        fi

        # ecdsa certs require different option to specify used key
        if [[ $cert =~ 'ecdsa' ]]; then
            options+=(-e ${cert}-server)
        else
            options+=(-n ${cert}-server)
        fi
        rlRun "expect $EXPECTS/nss-server.expect ${options[*]} \
               >server.log 2>server.err &"
        nss_pid=$!
        rlRun "rlWaitForSocket -d 0.1 4433 -p $nss_pid"
        [[ $DEBUG ]] && rlRun "rlWaitForFile -d 0.1 -p $tcpdump_pid capture.pcap"

        options=(openssl s_client)
        if [[ $sess_type == ' resume' ]]; then
            options+=(-sess_out sess.pem)
        fi
        options+=(-CAfile $(x509Cert ca))
        options+=(-key $(x509Key ${cert}-client))
        options+=(-cert $(x509Cert ${cert}-client))
        options+=(-connect localhost:4433)
        options+=(-keylogfile openssl_keylog.txt)
        options+=(-ciphersuites $C_OPENSSL)
        if [[ -n $OPENSSL_SIG ]]; then
            options+=(-sigalgs $OPENSSL_SIG)
        fi
        if [[ $g_type == ' HRR' ]]; then
            options+=(-groups $G_OPENSSL_HRR)
        elif [[ $G_OPENSSL ]]; then
            options+=(-groups $G_OPENSSL)
        fi

        if [[ $k_update == ' key update' ]]; then
            rlRun "expect $EXPECTS/openssl-rekey.expect ${options[*]} \
                   &> client.log"
        else
            rlRun "expect $EXPECTS/openssl-client.expect ${options[*]} \
                   &> client.log"
        fi

        rlAssertGrep 'GET / HTTP/1.0' client.log
        rlAssertGrep 'HTTP/1.0 200 OK' client.log
        rlAssertGrep "Cipher is $C_OPENSSL" client.log
        rlGetPhaseState
        if [[ $ECODE -gt $START_ECODE ]]; then
            rlRun 'cat server.log' 0 'Server stdout'
            rlRun 'cat server.err' 0 'Server stderr'
            rlRun 'cat client.log' 0 'Client output'
            [[ $DEBUG == 'shell' ]] && bash
        fi

        if [[ $sess_type == ' resume' ]]; then
            rlLogInfo 'Trying session resumption'
            options=(openssl s_client)
            options+=(-sess_in sess.pem)
            options+=(-CAfile $(x509Cert ca))
            options+=(-connect localhost:4433)
            options+=(-keylogfile openssl_keylog.txt)
            options+=(-key $(x509Key ${cert}-client))
            options+=(-cert $(x509Cert ${cert}-client))
            options+=(-ciphersuites $C_OPENSSL)
            if [[ -n $OPENSSL_SIG ]]; then
                options+=(-sigalgs $OPENSSL_SIG)
            fi
            if [[ $g_type == ' HRR' ]]; then
                options+=(-groups $G_OPENSSL_HRR)
            elif [[ $G_OPENSSL ]]; then
                options+=(-groups $G_OPENSSL)
            fi

            if [[ $k_update == ' key update' ]]; then
                rlRun "expect $EXPECTS/openssl-rekey.expect ${options[*]} \
                       &> client.log"
            else
                rlRun "expect $EXPECTS/openssl-client.expect ${options[*]} \
                       &> client.log"
            fi

            rlAssertGrep 'GET / HTTP/1.0' client.log
            rlAssertGrep 'HTTP/1.0 200 OK' client.log
            rlAssertGrep 'Reused, TLSv1.3' client.log
            rlGetPhaseState
            if [[ $ECODE -gt $START_ECODE ]]; then
                rlRun 'cat server.log' 0 'Server stdout'
                rlRun 'cat server.err' 0 'Server stderr'
                rlRun 'cat client.log' 0 'Client output'
                [[ $DEBUG == 'shell' ]] && bash
            fi
            rlLogInfo 'Second resume'
            options=(openssl s_client)
            options+=(-sess_in sess.pem)
            options+=(-CAfile $(x509Cert ca))
            options+=(-key $(x509Key ${cert}-client))
            options+=(-cert $(x509Cert ${cert}-client))
            options+=(-connect localhost:4433)
            options+=(-keylogfile openssl_keylog.txt)
            options+=(-ciphersuites $C_OPENSSL)
            if [[ -n $OPENSSL_SIG ]]; then
                options+=(-sigalgs $OPENSSL_SIG)
            fi
            if [[ $g_type == ' HRR' ]]; then
                options+=(-groups $G_OPENSSL_HRR)
            elif [[ $G_OPENSSL ]]; then
                options+=(-groups $G_OPENSSL)
            fi

            if [[ $k_update == ' key update' ]]; then
                rlRun "expect $EXPECTS/openssl-rekey.expect ${options[*]} \
                       &> client.log"
            else
                rlRun "expect $EXPECTS/openssl-client.expect ${options[*]} \
                       &> client.log"
            fi

            rlAssertGrep 'GET / HTTP/1.0' client.log
            rlAssertGrep 'HTTP/1.0 200 OK' client.log
            rlAssertGrep 'Reused, TLSv1.3' client.log
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


tls13interop_nss_openssl_cleanup() {
    if rlIsRHEL '<8.1' && ! $FIPS; then
        rlRun 'rlFileRestore'
    fi
}

tls13interop_nss_openssl_test_all_for_cert() { local cert=$1
    for c_name in "${tls13interop_nss_openssl_CIPHER_NAMES[@]}"; do
     for c_sig in 'default' 'SHA256' 'SHA384' 'SHA512'; do
      for g_name in "${tls13interop_nss_openssl_GROUP_NAMES[@]}"; do
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

          tls13interop_nss_openssl_test \
              "$cert" "$c_name" "$c_sig" "$g_name" \
              "$g_type" "$sess_type" "$k_update"

         done  # k_update
        done  # sess_type
       done  # g_type
      done  # g_name
     done  # c_sig
    done  # c_name
}


tls13interop_nss_openssl_test_all() {
    for cert in 'rsa' 'rsa-pss' 'ecdsa-p256' 'ecdsa-p384' 'ecdsa-p521'; do
        tls13interop_nss_openssl_test_all_for_cert $cert
    done
}
