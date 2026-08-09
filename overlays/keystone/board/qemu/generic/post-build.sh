#!/bin/sh
# Install the extlinux boot menu so U-Boot's distro boot finds the kernel that
# BR2_LINUX_KERNEL_INSTALL_TARGET placed in /boot/Image.
set -e

BOARD_DIR="$(dirname "$0")"

mkdir -p "${TARGET_DIR}/boot/extlinux"
install -m 0644 "${BOARD_DIR}/extlinux.conf" "${TARGET_DIR}/boot/extlinux/extlinux.conf"
