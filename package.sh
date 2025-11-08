#!/bin/sh
#

cargo build --release

if [ -d package ]; then
    rm -rf package
fi
if [ -d dist ]; then
    rm -rf dist
fi
mkdir -p package
mkdir -p dist
cp target/release/server package/
cp target/release/client package/
cp target/release/tcpserver package/
cp target/release/tcpclient package/
cp ca.pem package/
cp server.pem package/
cp client.pem package/
cp server.key package/
cp client.key package/

DATE_TAG=`date +%Y%m%d%H%M%S`
TMP_TARGET=/tmp/package-$DATE_TAG.tar.gz
tar zcvf $TMP_TARGET -C ./package "."
mv $TMP_TARGET dist/
