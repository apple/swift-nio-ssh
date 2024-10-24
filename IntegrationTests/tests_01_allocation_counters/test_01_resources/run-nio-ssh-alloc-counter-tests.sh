#!/bin/bash
##===----------------------------------------------------------------------===##
##
## This source file is part of the SwiftNIO open source project
##
## Copyright (c) 2019-2023 Apple Inc. and the SwiftNIO project authors
## Licensed under Apache License v2.0
##
## See LICENSE.txt for license information
## See CONTRIBUTORS.txt for the list of SwiftNIO project authors
##
## SPDX-License-Identifier: Apache-2.0
##
##===----------------------------------------------------------------------===##

set -eu
here="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# shellcheck disable=SC2154 # Provided by framework
tmp_dir="/tmp"

while getopts "t:" opt; do
    case "$opt" in
        t)
            tmp_dir="$OPTARG"
            ;;
        *)
            exit 1
            ;;
    esac
done

nio_checkout=$(mktemp -d "$tmp_dir/.swift-nio_XXXXXX")
(
cd "$nio_checkout"
git clone --depth 1 https://github.com/apple/swift-nio
)

shift $((OPTIND-1))

tests_to_run=("$here"/test_*.swift)

if [[ $# -gt 0 ]]; then
    tests_to_run=("$@")
fi

"$nio_checkout/swift-nio/IntegrationTests/allocation-counter-tests-framework/run-allocation-counter.sh" \
    -p "$here/../../.." \
    -m NIOCore \
    -m NIOEmbedded \
    -m NIOPosix \
    -m NIOSSH \
    -s "$here/shared.swift" \
    -t "$tmp_dir" \
    -d <( echo '.package(url: "https://github.com/apple/swift-nio.git", from: "2.32.0"),' ) \
    "${tests_to_run[@]}"
