#!/bin/bash

# copy from go/testdata to ts/testdata

set -eux

cd "$(dirname "$0")/.."

rm -rf ts/testdata
mkdir -p ts/testdata

cp -r go/testdata/* ts/testdata
