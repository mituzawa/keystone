#!/bin/sh
set -eu

# Install the extlinux configuration for U-Boot distro/bootstd boot
mkdir -p ${TARGET_DIR}/boot/extlinux
cp ${BR2_EXTERNAL_KEYSTONE_PATH}/board/eswin/hifive-premier-p550/extlinux.conf \
   ${TARGET_DIR}/boot/extlinux/extlinux.conf
