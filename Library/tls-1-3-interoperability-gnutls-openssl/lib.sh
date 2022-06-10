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
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   library-prefix = tls13interop_gnutls_openssl
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# Remember the library directory so that we'll know where to find .expect files
export tls13interop_gnutls_openssl_EXPECTS=$(realpath $(dirname $BASH_SOURCE))


function tls13interop_gnutls_opensslLibraryLoaded {( set -uex
    pushd /
    [[ -x $tls13interop_gnutls_openssl_EXPECTS/gnutls-client.expect ]]
    [[ -x $tls13interop_gnutls_openssl_EXPECTS/gnutls-resume.expect ]]
    [[ -x $tls13interop_gnutls_openssl_EXPECTS/openssl-client.expect ]]
    [[ -x $tls13interop_gnutls_openssl_EXPECTS/openssl-rekey.expect ]]
    popd
    return 0
)}

tls13interop_gnutls_openssl_CIPHER_NAMES=()
tls13interop_gnutls_openssl_CIPHER_NAMES+=('TLS_AES_128_GCM_SHA256')
tls13interop_gnutls_openssl_CIPHER_NAMES+=('TLS_AES_256_GCM_SHA384')
tls13interop_gnutls_openssl_CIPHER_NAMES+=('TLS_CHACHA20_POLY1305_SHA256')
tls13interop_gnutls_openssl_CIPHER_NAMES+=('TLS_AES_128_CCM_SHA256')
tls13interop_gnutls_openssl_CIPHER_NAMES+=('TLS_AES_128_CCM_8_SHA256')


tls13interop_gnutls_openssl_cipher_name_to_openssl() { local c_name=$1
    case $c_name in  # yeah, it's 1-to-1...
    'TLS_AES_128_GCM_SHA256') C_OPENSSL='TLS_AES_128_GCM_SHA256';;
    'TLS_AES_256_GCM_SHA384') C_OPENSSL='TLS_AES_256_GCM_SHA384';;
    'TLS_CHACHA20_POLY1305_SHA256') C_OPENSSL='TLS_CHACHA20_POLY1305_SHA256';;
    'TLS_AES_128_CCM_SHA256') C_OPENSSL='TLS_AES_128_CCM_SHA256';;
    'TLS_AES_128_CCM_8_SHA256') C_OPENSSL='TLS_AES_128_CCM_8_SHA256';;
    *) rlDie "No matching OpenSSL cipher for $c_name";;
    esac
    echo $C_OPENSSL
}


tls13interop_gnutls_openssl_GROUP_NAMES=()
tls13interop_gnutls_openssl_GROUP_NAMES+=('default')
tls13interop_gnutls_openssl_GROUP_NAMES+=('P-256')
tls13interop_gnutls_openssl_GROUP_NAMES+=('P-384')
tls13interop_gnutls_openssl_GROUP_NAMES+=('P-521')
tls13interop_gnutls_openssl_GROUP_NAMES+=('X25519')
if ! rlIsRHEL '<9'; then
    # X448 is not supported by GnuTLS in RHEL-8, added in RHEL-9
    tls13interop_gnutls_openssl_GROUP_NAMES+=('X448')
    # FFDHE is not supported by OpenSSL 1.1.1 RHBZ#1593671
    # https://github.com/openssl/openssl/issues/6519
    # added in RHEL-9 in OpenSSL
    tls13interop_gnutls_openssl_GROUP_NAMES+=('FFDHE2048')
    tls13interop_gnutls_openssl_GROUP_NAMES+=('FFDHE3072')
    tls13interop_gnutls_openssl_GROUP_NAMES+=('FFDHE4096')
    # # FFDHE 6144 is not supported by GnuTLS in RHEL-8
    tls13interop_gnutls_openssl_GROUP_NAMES+=('FFDHE6144')
    tls13interop_gnutls_openssl_GROUP_NAMES+=('FFDHE8192')
fi

tls13interop_gnutls_openssl_group_info() { local g_name=$1
    case $g_name in
    default)
        G_GNUTLS=''
        G_OPENSSL=''
        G_GNUTLS_HRR=''
        G_OPENSSL_HRR=''
        ;;
    P-256)
        G_GNUTLS=':-GROUP-ALL:+GROUP-SECP256R1'
        G_OPENSSL='P-256'
        G_GNUTLS_HRR=':-GROUP-ALL:+GROUP-SECP384R1:+GROUP-SECP256R1'
        G_OPENSSL_HRR='P-384:P-256'
    ;;
    P-384)
        G_GNUTLS=':-GROUP-ALL:+GROUP-SECP384R1'
        G_OPENSSL='P-384'
        G_GNUTLS_HRR=':-GROUP-ALL:+GROUP-SECP256R1:+GROUP-SECP384R1'
        G_OPENSSL_HRR='P-256:P-384'
    ;;
    P-521)
        G_GNUTLS=':-GROUP-ALL:+GROUP-SECP521R1'
        G_OPENSSL='P-521'
        G_GNUTLS_HRR=':-GROUP-ALL:+GROUP-SECP256R1:+GROUP-SECP521R1'
        G_OPENSSL_HRR='P-256:P-521'
    ;;
    X25519)
        G_GNUTLS=':-GROUP-ALL:+GROUP-X25519'
        G_OPENSSL='X25519'
        G_GNUTLS_HRR=':-GROUP-ALL:+GROUP-SECP256R1:+GROUP-X25519'
        G_OPENSSL_HRR='P-256:X25519'
    ;;
    X448)
       G_GNUTLS=':-GROUP-ALL:+GROUP-X448'
       G_OPENSSL='X448'
       G_GNUTLS_HRR=':-GROUP-ALL:+GROUP-SECP256R1:+GROUP-X448'
       G_OPENSSL_HRR='P-256:X448'
    ;;
    FFDHE2048)
        G_GNUTLS=':-GROUP-ALL:+GROUP-FFDHE2048'
        G_OPENSSL='ffdhe2048'
        G_GNUTLS_HRR=':-GROUP-ALL:+GROUP-FFDHE3072:+GROUP-FFDHE2048'
        G_OPENSSL_HRR='ffdhe4096:ffdhe2048'
    ;;
    FFDHE3072)
        G_GNUTLS=':-GROUP-ALL:+GROUP-FFDHE3072'
        G_OPENSSL='ffdhe3072'
        G_GNUTLS_HRR=':-GROUP-ALL:+GROUP-FFDHE2048:+GROUP-FFDHE3072'
        G_OPENSSL_HRR='ffdhe4096:ffdhe3072'
    ;;
    FFDHE4096)
        G_GNUTLS=':-GROUP-ALL:+GROUP-FFDHE4096'
        G_OPENSSL='ffdhe4096'
        G_GNUTLS_HRR=':-GROUP-ALL:+GROUP-FFDHE8192:+GROUP-FFDHE4096'
        G_OPENSSL_HRR='ffdhe2048:ffdhe4096'
    ;;
    FFDHE6144)
        G_GNUTLS=':-GROUP-ALL:+GROUP-FFDHE6144'
        G_OPENSSL='ffdhe6144'
        G_GNUTLS_HRR=':-GROUP-ALL:+GROUP-FFDHE4096:+GROUP-FFDHE6144'
        G_OPENSSL_HRR='ffdhe8192:ffdhe6144'
    ;;
    FFDHE8192)
        G_GNUTLS=':-GROUP-ALL:+GROUP-FFDHE8192'
        G_OPENSSL='ffdhe8192'
        G_GNUTLS_HRR=':-GROUP-ALL:+GROUP-FFDHE2048:+GROUP-FFDHE8192'
        G_OPENSSL_HRR='ffdhe3072:ffdhe8192'
    ;;
    *) rlDie "Unknown group name $g_name";;
    esac
    echo $G_GNUTLS $G_OPENSSL $G_GNUTLS_HRR $G_OPENSSL_HRR
}


tls13interop_clean_log() {
    # "GET / HTTP/1.0" and "HTTP/1.0 200 OK" are infrequently interrupted
    # by the likes of "read R BLOCK".
    # Clean the latter ones out.
    sed -z 's|read R BLOCK\n||' $1 > $2
}


tls13interop_gnutls_openssl_setup() {
    rlAssertRpm expect
    rlAssertRpm gnutls
    rlAssertRpm gnutls-utils
    rlAssertRpm openssl
    rlAssertRpm tcpdump

    rlRun "rlImport certgen"

    rlRun "rlImport fips"
    fipsIsEnabled && FIPS=true || FIPS=false

    rlRun 'x509KeyGen ca'
    rlRun 'x509KeyGen rsa-ca'
    rlRun 'x509KeyGen -t rsa-pss rsa-pss-ca'
    rlRun 'x509KeyGen -t ecdsa -s prime256v1 ecdsa-p256-ca'
    rlRun 'x509KeyGen -t ecdsa -s secp384r1 ecdsa-p384-ca'
    rlRun 'x509KeyGen -t ecdsa -s secp521r1 ecdsa-p521-ca'
    if ! $FIPS; then
        rlRun 'x509KeyGen -t Ed25519 ed25519-ca'
        rlRun 'x509KeyGen -t Ed448 ed448-ca'
    fi
    rlRun 'x509KeyGen rsa-server'
    rlRun 'x509KeyGen -t rsa-pss rsa-pss-server'
    rlRun 'x509KeyGen -t ecdsa -s prime256v1 ecdsa-p256-server'
    rlRun 'x509KeyGen -t ecdsa -s secp384r1 ecdsa-p384-server'
    rlRun 'x509KeyGen -t ecdsa -s secp521r1 ecdsa-p521-server'
    if ! $FIPS; then
        rlRun 'x509KeyGen -t Ed25519 ed25519-server'
        rlRun 'x509KeyGen -t Ed448 ed448-server'
    fi
    rlRun 'x509KeyGen rsa-client'
    rlRun 'x509KeyGen -t rsa-pss rsa-pss-client'
    rlRun 'x509KeyGen -t ecdsa -s prime256v1 ecdsa-p256-client'
    rlRun 'x509KeyGen -t ecdsa -s secp384r1 ecdsa-p384-client'
    rlRun 'x509KeyGen -t ecdsa -s secp521r1 ecdsa-p521-client'
    rlRun 'x509KeyGen -t ed25519 ed25519-client'
    rlRun 'x509KeyGen -t ed448 ed448-client'
    rlRun 'x509SelfSign ca'
    rlRun 'x509CertSign --CA ca -t ca --DN "CN=RSA CA" rsa-ca'
    rlRun 'x509CertSign --CA ca -t ca --DN "CN=RSA-PSS CA" rsa-pss-ca'
    rlRun 'x509CertSign --CA ca -t ca --DN "CN=P-256 ECDSA CA" ecdsa-p256-ca'
    rlRun 'x509CertSign --CA ca -t ca --DN "CN=P-384 ECDSA CA" ecdsa-p384-ca'
    rlRun 'x509CertSign --CA ca -t ca --DN "CN=P-521 ECDSA CA" ecdsa-p521-ca'
    if ! $FIPS; then
        rlRun 'x509CertSign --CA ca -t ca --DN "CN=Ed25519 EdDSA CA" ed25519-ca'
        rlRun 'x509CertSign --CA ca -t ca --DN "CN=Ed448 EdDSA CA" ed448-ca'
    fi
    rlRun 'x509CertSign --CA rsa-ca rsa-server'
    rlRun 'x509CertSign --CA rsa-pss-ca rsa-pss-server'
    rlRun 'x509CertSign --CA ecdsa-p256-ca ecdsa-p256-server'
    rlRun 'x509CertSign --CA ecdsa-p384-ca ecdsa-p384-server'
    rlRun 'x509CertSign --CA ecdsa-p521-ca ecdsa-p521-server'
    if ! $FIPS; then
        rlRun 'x509CertSign --CA ed25519-ca ed25519-server'
        rlRun 'x509CertSign --CA ed448-ca ed448-server'
    fi
    rlRun 'x509CertSign --CA rsa-ca -t webclient rsa-client'
    rlRun 'x509CertSign --CA rsa-pss-ca -t webclient rsa-pss-client'
    rlRun 'x509CertSign --CA ecdsa-p256-ca -t webclient ecdsa-p256-client'
    rlRun 'x509CertSign --CA ecdsa-p384-ca -t webclient ecdsa-p384-client'
    rlRun 'x509CertSign --CA ecdsa-p521-ca -t webclient ecdsa-p521-client'
    if ! $FIPS; then
        rlRun 'x509CertSign --CA ed25519-ca -t webclient ed25519-client'
        rlRun 'x509CertSign --CA ed448-ca -t webclient ed448-client'
    fi
    rlRun 'x509DumpCert ca' 0 'Root CA'
    rlRun 'x509DumpCert rsa-ca' 0 'Intermediate RSA CA'
    rlRun 'x509DumpCert rsa-pss-ca' 0 'Intermediate RSA-PSS CA'
    rlRun 'x509DumpCert ecdsa-p256-ca' 0 'Intermediate ECDSA CA'
    rlRun 'x509DumpCert ecdsa-p384-ca' 0 'Intermediate ECDSA CA'
    rlRun 'x509DumpCert ecdsa-p521-ca' 0 'Intermediate ECDSA CA'
    if ! $FIPS; then
        rlRun 'x509DumpCert ed25519-ca' 0 'Intermediate EdDSA CA'
        rlRun 'x509DumpCert ed448-ca' 0 'Intermediate EdDSA CA'
    fi
    rlRun 'x509DumpCert rsa-server' 0 'Server RSA certificate'
    rlRun 'x509DumpCert rsa-pss-server' 0 'Server RSA-PSS certificate'
    rlRun 'x509DumpCert ecdsa-p256-server' 0 'Server ECDSA certificate'
    rlRun 'x509DumpCert ecdsa-p384-server' 0 'Server ECDSA certificate'
    rlRun 'x509DumpCert ecdsa-p521-server' 0 'Server ECDSA certificate'
    if ! $FIPS; then
        rlRun 'x509DumpCert ed25519-server' 0 'Server EdDSA certificate'
        rlRun 'x509DumpCert ed448-server' 0 'Server EdDSA certificate'
    fi
    rlRun 'x509DumpCert rsa-client' 0 'Client RSA certificate'
    rlRun 'x509DumpCert rsa-pss-client' 0 'Client RSA-PSS certificate'
    rlRun 'x509DumpCert ecdsa-p256-client' 0 'Client ECDSA certificate'
    rlRun 'x509DumpCert ecdsa-p384-client' 0 'Client ECDSA certificate'
    rlRun 'x509DumpCert ecdsa-p521-client' 0 'Client ECDSA certificate'
    if ! $FIPS; then
        rlRun 'x509DumpCert ed25519-client' 0 'Client EdDSA certificate'
        rlRun 'x509DumpCert ed448-client' 0 'Client EdDSA certificate'
    fi
}


tls13interop_gnutls_openssl_test() {
    local cert=$1 c_name=$2 c_sig=$3
    local g_name=$4 g_type=$5 sess_type=$6 k_update=$7
    rlGetPhaseState
    local START_ECODE=$ECODE

    if [[ $g_type == ' HRR' && $g_name == 'default' ]]; then
        rlDie "Do not use HRR with default key exchange as by default all groups are enabled"
    fi

    if ! [[ $cert =~ rsa ]] && [[ $c_sig != 'default' ]]; then
        rlDie "cert $cert c_sig $c_sig invalid: for ECDSA, the hash is bound to the key type"
    fi

    if $FIPS && [[ $c_name = TLS_CHACHA20_POLY1305_SHA256 ]]; then
        rlDie "CHACHA20_POLY1305 is not allowed in FIPS mode"
    fi

    if $FIPS && [[ $cert =~ ^ed ]]; then
        rlDie "$cert is not allowed in FIPS mode"
    fi

    if $FIPS && ( [[ $g_name = X25519 ]] || [[ $g_name = X448 ]] ); then
        rlDie "X25519 and X448 are not allowed in FIPS mode"
    fi

    local EXPECTS=$tls13interop_gnutls_openssl_EXPECTS
    export SSLKEYLOGFILE=key_log_file.txt
    local GNUTLS_PRIO="NORMAL:+VERS-TLS1.3:+AES-128-CCM-8"

    local C_OPENSSL
    C_OPENSSL=$(tls13interop_gnutls_openssl_cipher_name_to_openssl $c_name)

    local G_GNUTLS G_OPENSSL G_GNUTLS_HRR G_OPENSSL_HRR
    read G_GNUTLS G_OPENSSL G_GNUTLS_HRR G_OPENSSL_HRR \
        <<<$(tls13interop_gnutls_openssl_group_info $g_name)

    if [[ $c_sig != 'default' ]]; then
        if [[ $cert == rsa ]]; then
            GNUTLS_SIG=":-SIGN-ALL:+SIGN-RSA-PSS-RSAE-$c_sig"
            OPENSSL_SIG="rsa_pss_rsae_${c_sig,,}"
        else
            GNUTLS_SIG=":-SIGN-ALL:+SIGN-RSA-PSS-$c_sig"
            OPENSSL_SIG="rsa_pss_pss_${c_sig,,}"
        fi
    else
        GNUTLS_SIG=""
        OPENSSL_SIG=""
    fi

    if [[ $tls13interop_no_phases ]]; then
        rlLogInfo "::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::"
        rlLogInfo "::  GnuTLS server OpenSSL client $c_name cipher $cert cert $c_sig sig_alg $g_name kex$g_type$sess_type$k_update"
        rlLogInfo "::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::"
    else
        rlPhaseStartTest "GnuTLS server OpenSSL client $c_name cipher $cert cert $c_sig sig_alg $g_name kex$g_type$sess_type$k_update"
    fi
        [[ $DEBUG ]] && rlRun "tcpdump -i lo -B 1024 -s 0 -U -w capture.pcap port 4433 &"
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
            rlRun "expect -d $EXPECTS/openssl-rekey.expect ${options[*]} \
                   > client.log 2> client.err"
        else
            rlRun "expect -d $EXPECTS/openssl-client.expect ${options[*]} \
                   > client.log 2> client.err"
        fi

        tls13interop_clean_log client.log client.log.cleaner
        rlAssertGrep "GET / HTTP/1.0" client.log.cleaner
        rlAssertGrep "HTTP/1.0 200 OK" client.log.cleaner
        rlAssertGrep "Cipher is $C_OPENSSL" client.log.cleaner
        rlGetPhaseState
        if [[ $ECODE -gt $START_ECODE ]]; then
            rlRun "cat client.log" 0 "Client output"
            rlRun "cat client.err" 0 "Client error output"
            [[ $DEBUG ]] && bash
        fi

        if [[ $sess_type == ' resume' ]]; then
            rlLogInfo "Trying session resumption"
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

            rlRun "expect $EXPECTS/openssl-client.expect ${options[*]} \
                   &> client.log"

            tls13interop_clean_log client.log client.log.cleaner
            rlAssertGrep "GET / HTTP/1.0" client.log.cleaner
            rlAssertGrep "HTTP/1.0 200 OK" client.log.cleaner
            rlAssertGrep "Reused, TLSv1.3" client.log.cleaner
            rlGetPhaseState
            if [[ $ECODE -gt $START_ECODE ]]; then
                rlRun "cat client.log" 0 "Client output"
                [[ $DEBUG ]] && bash
            fi

            rlLogInfo "Second resume"
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

            rlRun "expect $EXPECTS/openssl-client.expect ${options[*]} \
                   &> client.log"

            tls13interop_clean_log client.log client.log.cleaner
            rlAssertGrep "GET / HTTP/1.0" client.log.cleaner
            rlAssertGrep "HTTP/1.0 200 OK" client.log.cleaner
            rlAssertGrep "Reused, TLSv1.3" client.log.cleaner
            rlGetPhaseState
            if [[ $ECODE -gt $START_ECODE ]]; then
                rlRun "cat client.log" 0 "Client output"
                [[ $DEBUG ]] && bash
            fi
        fi

        rlRun "kill $gnutls_pid"
        rlRun "rlWait -s 9 $gnutls_pid" 1
        [[ $DEBUG ]] && rlRun "rlWait -s 9 $sleep_pid"
        [[ $DEBUG ]] && rlRun "kill $tcpdump_pid"
        [[ $DEBUG ]] && rlRun "rlWait -s 9 $tcpdump_pid"
        rlGetPhaseState
        if [[ $ECODE -gt $START_ECODE ]]; then
            rlRun "cat server.log" 0 "Server stdout"
            rlRun "cat server.err" 0 "Server stderr"
            rlRun "cat client.log" 0 "Client output"
            [[ $DEBUG ]] && bash
        fi
    if [[ $tls13interop_no_phases ]]; then
        rlLogInfo "::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::"
        rlLogInfo ""
        rlLogInfo "::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::"
        rlLogInfo "::  OpenSSL server GnuTLS client $c_name cipher $cert cert $c_sig sig_alg $g_name kex$g_type$sess_type$k_update"
        rlLogInfo "::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::"
    else
        rlPhaseEnd

        rlPhaseStartTest "OpenSSL server GnuTLS client $c_name cipher $cert cert $c_sig sig_alg $g_name kex$g_type$sess_type$k_update"
    fi
        [[ $DEBUG ]] && rlRun "tcpdump -i lo -B 1024 -s 0 -U -w capture.pcap port 4433 &"
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
            rlRun "expect $EXPECTS/gnutls-resume.expect ${options[*]} \
                   &> client.log" \
                  0,1
        else
            rlRun "expect $EXPECTS/gnutls-client.expect ${options[*]} \
                   &> client.log" \
                  0,1
        fi

        tls13interop_clean_log client.log client.log.cleaner
        rlAssertGrep "GET / HTTP/1.0" client.log.cleaner
        rlAssertGrep "HTTP/1.0 200 ok" client.log.cleaner
        rlAssertGrep $C_OPENSSL client.log.cleaner
        if [[ $sess_type == ' resume' ]]; then
            rlAssertGrep "Resume Handshake was completed" client.log.cleaner
            rlAssertGrep "This is a resumed session" client.log.cleaner
        fi
        rlRun "kill $openssl_pid"
        rlRun "rlWait -s 9 $openssl_pid" 143
        [[ $DEBUG ]] && rlRun "rlWait -s 9 $sleep_pid"
        [[ $DEBUG ]] && rlRun "kill $tcpdump_pid"
        [[ $DEBUG ]] && rlRun "rlWait -s 9 $tcpdump_pid"
        rlGetPhaseState
        if [[ $ECODE -gt $START_ECODE ]]; then
            rlRun "cat server.log" 0 "Server stdout"
            rlRun "cat server.err" 0 "Server stderr"
            rlRun "cat client.log" 0 "Client output"
            [[ $DEBUG ]] && bash
        fi
    if [[ $tls13interop_no_phases ]]; then
        rlLogInfo "::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::"
        rlLogInfo ""
        rlLogInfo "::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::"
        rlLogInfo "::  GnuTLS server OpenSSL client $c_name cipher $cert client cert $c_sig sig_alg $g_name kex$g_type$sess_type$k_update"
        rlLogInfo "::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::"
    else
        rlPhaseEnd

        rlPhaseStartTest "GnuTLS server OpenSSL client $c_name cipher $cert client cert $c_sig sig_alg $g_name kex$g_type$sess_type$k_update"
    fi
        [[ $DEBUG ]] && rlRun "tcpdump -i lo -B 1024 -s 0 -U -w capture.pcap port 4433 &"
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

        tls13interop_clean_log client.log client.log.cleaner
        rlAssertGrep "GET / HTTP/1.0" client.log.cleaner
        rlAssertGrep "HTTP/1.0 200 OK" client.log.cleaner
        rlAssertGrep "Cipher is $C_OPENSSL" client.log.cleaner
        rlGetPhaseState
        if [[ $ECODE -gt $START_ECODE ]]; then
            rlRun "cat client.log" 0 "Client output"
            [[ $DEBUG ]] && bash
        fi

        if [[ $sess_type == ' resume' ]]; then
            rlLogInfo "Trying session resumption"
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

            rlRun "expect $EXPECTS/openssl-client.expect ${options[*]} \
                   &> client.log"

            tls13interop_clean_log client.log client.log.cleaner
            rlAssertGrep "GET / HTTP/1.0" client.log.cleaner
            rlAssertGrep "HTTP/1.0 200 OK" client.log.cleaner
            rlAssertGrep "Reused, TLSv1.3" client.log.cleaner
            rlGetPhaseState
            if [[ $ECODE -gt $START_ECODE ]]; then
                rlRun "cat client.log" 0 "Client output"
                [[ $DEBUG ]] && bash
            fi

            rlLogInfo "Second resume"
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

            rlRun "expect $EXPECTS/openssl-client.expect ${options[*]} \
                   &> client.log"

            tls13interop_clean_log client.log client.log.cleaner
            rlAssertGrep "GET / HTTP/1.0" client.log.cleaner
            rlAssertGrep "HTTP/1.0 200 OK" client.log.cleaner
            rlAssertGrep "Reused, TLSv1.3" client.log.cleaner
            rlGetPhaseState
            if [[ $ECODE -gt $START_ECODE ]]; then
                rlRun "cat client.log" 0 "Client output"
                [[ $DEBUG ]] && bash
            fi
        fi

        rlRun "kill $gnutls_pid"
        rlRun "rlWait -s 9 $gnutls_pid" 1
        [[ $DEBUG ]] && rlRun "rlWait -s 9 $sleep_pid"
        [[ $DEBUG ]] && rlRun "kill $tcpdump_pid"
        [[ $DEBUG ]] && rlRun "rlWait -s 9 $tcpdump_pid"
        rlGetPhaseState
        if [[ $ECODE -gt $START_ECODE ]]; then
            rlRun "cat server.log" 0 "Server stdout"
            rlRun "cat server.err" 0 "Server stderr"
            rlRun "cat client.log" 0 "Client output"
            [[ $DEBUG ]] && bash
        fi
    if [[ $tls13interop_no_phases ]]; then
        rlLogInfo "::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::"
        rlLogInfo ""
        rlLogInfo "::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::"
        rlLogInfo "::  OpenSSL server GnuTLS client $c_name cipher $cert client cert $c_sig sig_alg $g_name kex$g_type$sess_type$k_update"
        rlLogInfo "::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::"
    else
        rlPhaseEnd

        rlPhaseStartTest "OpenSSL server GnuTLS client $c_name cipher $cert client cert $c_sig sig_alg $g_name kex$g_type$sess_type$k_update"
    fi
        [[ $DEBUG ]] && rlRun "tcpdump -i lo -B 1024 -s 0 -U -w capture.pcap port 4433 &"
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
        options+=(-Verify 3)
        rlRun "${options[*]} >server.log 2>server.err &"
        openssl_pid=$!
        rlRun "rlWaitForSocket -d 0.1 4433 -p $openssl_pid"
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
            rlRun "expect $EXPECTS/gnutls-resume.expect ${options[*]} \
                   &> client.log" \
                  0,1
        else
            rlRun "expect $EXPECTS/gnutls-client.expect ${options[*]} \
                   &> client.log" \
                  0,1
        fi

        tls13interop_clean_log client.log client.log.cleaner
        rlAssertGrep "GET / HTTP/1.0" client.log.cleaner
        rlAssertGrep "HTTP/1.0 200 ok" client.log.cleaner
        rlAssertGrep "$C_OPENSSL" client.log.cleaner
        if [[ $sess_type == ' resume' ]]; then
            rlAssertGrep "Resume Handshake was completed" client.log.cleaner
            rlAssertGrep "This is a resumed session" client.log.cleaner
        fi
        rlRun "kill $openssl_pid"
        rlRun "rlWait -s 9 $openssl_pid" 143
        [[ $DEBUG ]] && rlRun "rlWait -s 9 $sleep_pid"
        [[ $DEBUG ]] && rlRun "kill $tcpdump_pid"
        [[ $DEBUG ]] && rlRun "rlWait -s 9 $tcpdump_pid"
        rlGetPhaseState
        if [[ $ECODE -gt $START_ECODE ]]; then
            rlRun "cat server.log" 0 "Server stdout"
            rlRun "cat server.err" 0 "Server stderr"
            rlRun "cat client.log" 0 "Client output"
            [[ $DEBUG ]] && bash
        fi
    if [[ $tls13interop_no_phases ]]; then
        rlLogInfo "::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::"
        rlLogInfo ""
    else
        rlPhaseEnd
    fi

    unset SSLKEYLOGFILE
}


tls13interop_gnutls_openssl_test_all_for_cert() { local cert=$1
    for c_name in "${tls13interop_gnutls_openssl_CIPHER_NAMES[@]}"; do
     for c_sig in 'default' 'SHA256' 'SHA384' 'SHA512'; do
      for g_name in "${tls13interop_gnutls_openssl_GROUP_NAMES[@]}"; do
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
          if $FIPS && ( [[ $g_name = X25519 ]] || [[ $g_name = X448 ]] ); then
              continue
          fi

          tls13interop_gnutls_openssl_test \
              "$cert" "$c_name" "$c_sig" "$g_name" \
              "$g_type" "$sess_type" "$k_update"

         done  # k_update
        done  # sess_type
       done  # g_type
      done  # g_name
     done  # c_sig
    done  # c_name
}


tls13interop_gnutls_openssl_test_all() {
    for cert in 'rsa' 'rsa-pss' 'ecdsa-p256' 'ecdsa-p384' 'ecdsa-p521'; do
        tls13interop_gnutls_openssl_test_all_for_cert $cert
    done
}
