#!/usr/bin/env bash

OSZA_URL=$1
RUNTIME_URL="https://github.com/AppImage/AppImageKit/releases/download/continuous/runtime-x86_64"

if [ -z "$OSZA_URL" ]; then
    echo "No url specified!"
    exit 1
fi

source /root/env.sh
source /opt/rh/devtoolset-4/enable

cd /root

wget $RUNTIME_URL -O runtime

wget $OSZA_URL -O osza.tar.xz
tar xf osza.tar.xz
cd osza-*

/root/build-appimage.sh \
    --sourcedir=`pwd` \
    --outdir=/out \
    --runtime=/root/runtime \
    --qmake=$QTDIR/bin/qmake
