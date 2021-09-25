#!/bin/bash

set -e

npm run build

TMP="$(mktemp --suffix=-knocksvc-build -d)"

cleanup()
{
    echo "Cleaning up temporary directory $TMP"
    rm -r "$TMP"
}

trap cleanup EXIT

cp "./dist/main.js" "$TMP/index.js"
cp -r ./res "$TMP/"

cd "$TMP" || exit 1
tar c . > "$OLDPWD/knocksvc-build.tar" || exit 1

echo "[+] Built knocksvc-build.tar"
