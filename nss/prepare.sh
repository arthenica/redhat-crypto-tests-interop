#!/bin/bash

echo "Hello from TLS interoperability prepare script for NSS"

apt-get update \
 && apt-get install -y --no-install-recommends \
    python3.9 \
    python3-pip \
    rsync \
    iproute2 \
    libnss3-tools \
    expect \
    gnutls-bin \
    crypto-policies \
 && echo "Installed successfully"
# && rm -rf /var/lib/apt/lists/* \
# && apt-get autoremove -y && apt-get clean -y

ln -sf /usr/bin/python3.9 /usr/bin/python3 && \
pip install tmt && \
echo '#!/bin/bash\n\nexit 0' >/usr/bin/fakedora && \
chmod +x /usr/bin/fakedora && \
ln -s /usr/bin/fakedora /usr/bin/rpm && \
ln -s /usr/bin/fakedora /usr/bin/dnf && \
mkdir -p /usr/lib/nss/unsupported-tools/ && \
ln -s /usr/bin/selfserv /usr/lib/nss/unsupported-tools/selfserv && \
ln -s /usr/bin/tstclnt /usr/lib/nss/unsupported-tools/tstclnt && \
ln -s /usr/bin/strsclnt /usr/lib/nss/unsupported-tools/strsclnt && \
update-crypto-policies --set DEFAULT && \
pushd $HOME && \
git clone --branch=nss-v0.1 --depth=1 https://gitlab.com/redhat-crypto/tests/interop.git && \
curl -L -o beakerlib.tgz 'https://github.com/beakerlib/beakerlib/archive/refs/tags/1.31.4.tar.gz' && \
tar xf beakerlib.tgz && \
cd beakerlib-* && \
make install && \
popd && \
echo "Preparation done, dir: $(pwd)"
