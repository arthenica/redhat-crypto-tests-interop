#!/bin/bash

# How to run this:
#   bash <path_to_dir>/sync.sh <path_to_root_of_downstream_test_git_repos>

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
        "openssl/Library/tls-1-3-interoperability-nss-openssl"
        "gnutls/Library/tls-1-3-interoperability-gnutls-nss/"
        # tests: openssl <-> gnutls
        "openssl/Interoperability/tls-1-3-interoperability-gnutls-openssl-2way"
        "openssl/Interoperability/tls-1-3-interoperability-gnutls-openssl-3way"
        "openssl/Interoperability/CC-openssl-with-gnutls"
        "gnutls/Interoperability/TLSv1-2-with-OpenSSL"
        "gnutls/Interoperability/certificates-with-OpenSSL"
        "gnutls/Interoperability/keymatexport-with-OpenSSL"
        "gnutls/Interoperability/renegotiation-with-OpenSSL"
        "gnutls/Interoperability/resumption-with-OpenSSL"
        "gnutls/Interoperability/softhsm-integration"
        # tests: nss <-> gnutls (TODO)
        "gnutls/Interoperability/tls-1-3-interoperability-gnutls-nss-2way"
        "gnutls/Interoperability/tls-1-3-interoperability-gnutls-nss-3way"
        "gnutls/Interoperability/TLSv1-2-with-NSS"
	"gnutls/Interoperability/renegotiation-with-NSS"
        # tests: nss <-> openssl (TODO)
        "openssl/Interoperability/tls-1-3-interoperability-nss-openssl-2way"
        "nss/Interoperability/renego-and-resumption-NSS-with-OpenSSL"
        "nss/Interoperability/CC-nss-with-openssl"
)

EXCLUDED_FILES=(
        # files to be excluded in rsync
        "expectedness.yml"
)

repourl="https://gitlab.com/redhat-crypto/tests/interop.git"
reponame="interop"

for t in ${TESTS[@]}; do
    echo
    echo $t

    sdir="$source_root/$t"
    debug "Source dir: $sdir"
    if [[ "$t" != *"/Library/"* ]]; then
        parent=${t%%/*}
        debug "Parent repo: $parent"
        testname=${t##*/}
        debug "Test name: $testname"
        ddir="$dest_root/Interoperability/${parent}_$testname"
    else
        ddir="$dest_root/${t#*/}"
    fi
    debug "Dest dir: $ddir"
    mkdir -p $ddir
    debug "$sdir -> $ddir"
    EXCLUDE=""
    for i in ${EXCLUDED_FILES[@]}; do EXCLUDE="$EXCLUDE --exclude ${i}"; done;
    rsync -a $EXCLUDE $sdir/ $ddir/ || fail "rsync"

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

        # ugly hack to remove empty "require"s
        cat $ddir/main.fmf |awk '/^require:$/ { req=1; next } /^recommend:$/ { if (req) { req=0; print; next } } { if (req) { req=0; print "require:"; } print }' >$ddir/main.fmf.new
        mv $ddir/main.fmf.new $ddir/main.fmf
    fi
    if [[ $scriptfile = "runtest.sh" && -r $ddir/main.fmf ]]; then
        grep -qw interop $ddir/main.fmf || fail "no 'interop' tag"
    fi
    if [[ -r $ddir/Makefile ]]; then
        echo "  Makefile"
        sed -i "/RhtsRequires:/d" $ddir/Makefile
    fi
done
