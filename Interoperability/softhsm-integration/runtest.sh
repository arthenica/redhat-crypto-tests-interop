#!/bin/bash
# vim: dict+=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/gnutls/Interoperability/softhsm-integration
#   Description: Integration with softhsm PKCS#11 module.
#   Author: Stanislav Zidek <szidek@redhat.com>
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Copyright (c) 2016 Red Hat, Inc.
#
#   This program is free software: you can redistribute it and/or
#   modify it under the terms of the GNU General Public License as
#   published by the Free Software Foundation, either version 2 of
#   the License, or (at your option) any later version.
#
#   This program is distributed in the hope that it will be
#   useful, but WITHOUT ANY WARRANTY; without even the implied
#   warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
#   PURPOSE.  See the GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program. If not, see http://www.gnu.org/licenses/.
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# Include Beaker environment
. /usr/share/beakerlib/beakerlib.sh || exit 1

PACKAGE="gnutls"

SH_CONF="softhsm.conf"
SH_PROVIDER="/usr/lib64/pkcs11/libsofthsm2.so"
SH_PIN=1234

rlJournalStart
    rlPhaseStartSetup
        rlAssertRpm $PACKAGE
        rlRun "TmpDir=\$(mktemp -d)" 0 "Creating tmp directory"
        rlRun "pushd $TmpDir"

    rlPhaseStartTest "Generate key and cert"
        cat >$SH_CONF <<_EOF
directories.tokendir = ./db
objectstore.backend = file
_EOF
        rlRun "mkdir db"
        rlRun "export SOFTHSM2_CONF=./$SH_CONF"
        rlRun "softhsm2-util --init-token --slot 0 --label test --so-pin $SH_PIN --pin $SH_PIN" 0 \
            "Initialize token"
        options=(
                "--batch" "--login"
                "--outfile publickey"
                "--generate-rsa" "--label rsa"
                "--provider $SH_PROVIDER"
                )
        rlRun "GNUTLS_PIN=$SH_PIN p11tool ${options[*]}" 0 "Generate key and cert"
    rlPhaseEnd

    rlPhaseStartTest "Public keys not marked as private - bz1339453"
        options=(
                "--batch" "--list-all"
                "--provider $SH_PROVIDER"
                )
        rlRun -s "GNUTLS_PIN=$SH_PIN p11tool --login ${options[*]}" 0 "List all objects"
        rlAssertEquals "Expected two objects in total (private & public key)" \
            $(grep -c "^Object" $rlRun_LOG) 2
        rlAssertGrep "Type: Private key" $rlRun_LOG
        rlAssertGrep "Type: Public key" $rlRun_LOG
        rm -f $rlRun_LOG
        rlRun -s "p11tool ${options[*]}" 0 "List public objects"
        rlAssertEquals "Expected just one non-private object (public key)" \
            $(grep -c "^Object" $rlRun_LOG) 1
        rlAssertGrep "Type: Public key" $rlRun_LOG
        rm -f $rlRun_LOG
    rlPhaseEnd

    if ! rlIsRHEL '<8'; then
    rlPhaseStartTest "PKCS#11 URI without module/token/provider/serial specification - bz1705478"
        options=(
                "--batch"
                "--list-all"
                "--login"
                )
        rlRun -s "GNUTLS_PIN=$SH_PIN p11tool --provider $SH_PROVIDER ${options[*]}" 0 \
            "List all softhsm objects"
        for uri in `cat $rlRun_LOG |grep 'URL:' |awk '{print $NF}'`; do
            rlRun "GNUTLS_PIN=$SH_PIN p11tool ${options[*]} '$uri'" 0 "List object by URI"
            uri_notoken=$(echo "$uri" \
                |sed 's/model=[^;]*;*//g' \
                |sed 's/manufacturer=[^;]*;*//g' \
                |sed 's/serial=[^;]*;*//g' \
                |sed 's/token=[^;]*;*//g' \
                )
            rlRun "GNUTLS_PIN=$SH_PIN p11tool ${options[*]} '$uri_notoken'" 0 \
                "List object by URI without module specification"
            uri_id=$(echo "$uri" |sed 's/^pkcs11:\(.*;\)*\(id=[^;]*\).*$/pkcs11:\2/')
            rlRun "GNUTLS_PIN=$SH_PIN p11tool ${options[*]} '$uri_id'" 0 \
                "List object by URI with just id"
        done
        rm -f $rlRun_LOG
    rlPhaseEnd
    fi

    rlPhaseStartCleanup
        rlRun "popd"
        rlRun "rm -r $TmpDir" 0 "Removing tmp directory"
    rlPhaseEnd
rlJournalPrintText
rlJournalEnd
