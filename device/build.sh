#!/bin/bash
set -e

OUT="build"
mkdir -p "$OUT"

targets=(
    "linux 386     x86"
    "linux arm 7   armv7l"
    "linux arm 5   armv5l"
    "linux arm64   armv8l"
    "linux mips    mips"
    "linux mipsle  mipsel"
)

for entry in "${targets[@]}"; do
    read -ra t <<< "$entry"
    export GOOS="${t[0]}" GOARCH="${t[1]}"
    name="${t[-1]}"
    unset GOARM
    if [[ "${t[1]}" == "arm" ]]; then
        export GOARM="${t[2]}"
    fi
    echo "building $name (GOOS=$GOOS GOARCH=$GOARCH GOARM=${GOARM:-n/a})"
    go build -ldflags="-s -w" -o "$OUT/$name" .
done

echo "done — binaries in $OUT/"