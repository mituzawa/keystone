#!/bin/sh
set -e

cd ~/github/keystone
git apply --check ./MyPatches/keystone_options.patch
git apply ./MyPatches/keystone_options.patch
