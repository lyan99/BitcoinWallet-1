#!/bin/sh
#########################
# Package BitcoinWallet #
#########################

if [ -z "$1" ] ; then
  echo "You must specify the version to package"
  exit 1
fi

VERSION="$1"

if [ ! -f target/BitcoinWallet-$VERSION.jar ] ; then
  echo "You must build the BitcoinWallet-$VERSION.jar file"
  exit 1
fi

cd package
rm lib/*
cp ../LICENSE ../README.md ../sample.BitcoinWallet.conf ../sample.logging.properties .
cp ../target/BitcoinWallet-$VERSION.jar .
cp ../target/lib/* lib

if [ -f BitcoinWallet-$VERSION.zip ] ; then
  rm BitcoinWallet-$VERSION.zip
fi
zip -r BitcoinWallet-$VERSION.zip BitcoinWallet-$VERSION.jar lib LICENSE README.md sample.BitcoinWallet.conf sample.logging.properties
echo "Created BitcoinWallet-$VERSION.zip"

if [ -f BitcoinWallet-$VERSION.tar.gz ] ; then
  rm BitcoinWallet-$VERSION.tar.gz
fi
tar zchf BitcoinWallet-$VERSION.tar.gz BitcoinWallet-$VERSION.jar lib LICENSE README.md sample.BitcoinWallet.conf sample.logging.properties
echo "Created BitcoinWallet-$VERSION.tar.gz"
exit 0

