#!/usr/bin/env bash

function die() {
  echo "$@"
  exit 1
}

set -e

rm -rf https-everywhere
git clone --depth 1 https://github.com/EFForg/https-everywhere.git || die "Could not clone https everywhere?"

go build || die "Could not build"
./preprocess || die "Error preprocessing?"

go get -u github.com/jteeuwen/go-bindata/...
go-bindata -pkg httpseverywhere -o ../gobrulesets.go ./rulesets.gob
