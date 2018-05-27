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

if [ ! -d package ] ; then
  mkdir package
else
  rm -r package/*
fi

cd package
cp ../ChangeLog.txt ../LICENSE ../README.md ../sample.BitcoinWallet.conf ../sample.logging.properties .
cp -r ../target/BitcoinWallet-$VERSION.jar ../target/lib .

zip -r BitcoinWallet-$VERSION.zip BitcoinWallet-$VERSION.jar lib ChangeLog.txt LICENSE README.md sample.BitcoinWallet.conf sample.logging.properties
echo "Created BitcoinWallet-$VERSION.zip"

tar zchf BitcoinWallet-$VERSION.tar.gz BitcoinWallet-$VERSION.jar lib ChangeLog.txt LICENSE README.md sample.BitcoinWallet.conf sample.logging.properties
echo "Created BitcoinWallet-$VERSION.tar.gz"
exit 0

