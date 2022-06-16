#!/bin/bash

fail() {
    if [[ -n $1 ]]; then
        message="Error: $1"
    else
        message="Error (unspecified)"
    fi
    echo >&2 "$message"
    exit 1
}

#DEBUG=1
debug() {
    if [[ -n $DEBUG ]]; then
        echo "Debug: $*"
    fi
}

source_root=$1
[[ -n $source_root ]] || fail "unspecified source dir"

# destination root is the directory of this script
dest_root="$( cd -- "$( dirname -- "${BASH_SOURCE[0]:-$0}"; )" &> /dev/null && pwd 2> /dev/null; )";
echo "Destination root: $dest_root"

TESTS=(
        # libraries
        "distribution/Library/fips"
        "openssl/Library/certgen"
        "openssl/Library/tls-1-3-interoperability-gnutls-openssl"
        "gnutls/Library/tls-1-3-interoperability-gnutls-nss/"
        # tests
        #"openssl/Interoperability/tls-1-3-interoperability-gnutls-openssl-2way"
        #"gnutls/Interoperability/tls-1-3-interoperability-gnutls-nss-2way"
        #"openssl/Interoperability/tls-1-3-interoperability-gnutls-openssl-3way"
        #"gnutls/Interoperability/tls-1-3-interoperability-gnutls-nss-3way"
        "openssl/Interoperability/tls-1-3-interoperability-gnutls-openssl-2way"
        "openssl/Interoperability/tls-1-3-interoperability-gnutls-openssl-3way"
        "openssl/Interoperability/tls-1-3-interoperability-gnutls-openssl-4way"
        "openssl/Interoperability/tls-1-3-interoperability-gnutls-openssl-5way"
        "openssl/Interoperability/tls-1-3-interoperability-gnutls-openssl-p256"
        "openssl/Interoperability/tls-1-3-interoperability-gnutls-openssl-p384"
        "openssl/Interoperability/tls-1-3-interoperability-gnutls-openssl-p521"
        "openssl/Interoperability/tls-1-3-interoperability-gnutls-openssl-rsae"
        "openssl/Interoperability/tls-1-3-interoperability-gnutls-openssl-rsapss"
)

repourl="https://gitlab.com/redhat-crypto/tests/experimental-interop.git"
reponame="experimental-interop"

for t in ${TESTS[@]}; do
    echo
    echo $t
    #test -r $source_root/$t/runtest.sh || fail "$t: no test script" # TODO why are we doing this?

    sdir="$source_root/$t"
    debug "Source dir: $sdir"
    ddir="$dest_root/${t#*/}"
    debug "Dest dir: $ddir"
    mkdir -p $ddir
    debug "$sdir -> $ddir"
    rsync -a $sdir/ $ddir/ || fail "rsync"

    if [[ -r $ddir/lib.sh ]]; then
        debug "Handling test library"
        scriptfile="lib.sh"
    elif [[ -r $ddir/runtest.sh ]]; then
        debug "Handling regular test"
        scriptfile="runtest.sh"
    else
        fail "unknown dir type"
    fi

    echo "Remapping:"
    while read line; do
        debug "read line: $line"
        lib=$(echo $line |sed 's/^.*rlImport[ ]*\([^ "]*\).*$/\1/')
        libc=${lib%/*}
        libn=${lib#*/}
        echo "  Libname: $lib = $libc / $libn"
        sed -i "s|rlImport[ ]*$libc[ ]*/[ ]*$libn|rlImport $libn|g" $ddir/$scriptfile
    done < <(cat $ddir/$scriptfile |grep '^[^#]*rlImport')

    echo "  FMF medatada"
    if [[ ${t%%/*} != "distribution" && ! -r $source_root/$t/main.fmf ]]; then
        fail "$t: no FMF metadata"
    fi
    if [[ -r $source_root/$t/main.fmf ]]; then
        sed -i "/[ ]*-[ ]*library[ ]*([^)]*)/d" $ddir/main.fmf # remove libs from long lists
        sed -i "s/library[ ]*([^)]*)[ ,]*//g" $ddir/main.fmf # remove libs from short lists
    fi
    if [[ $scriptfile = "runtest.sh" && -r $ddir/main.fmf ]]; then
        grep -qw interop $ddir/main.fmf || fail "no 'interop' tag"
    fi
    if [[ -r $ddir/Makefile ]]; then
        echo "  Makefile"
        sed -i "/RhtsRequires:/d" $ddir/Makefile
    fi
done
