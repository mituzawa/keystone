# overlays/keystone/package/wasi-sdk/wasi-sdk.mk

HOST_WASI_SDK_VERSION = 33.0
HOST_WASI_SDK_SOURCE = wasi-sdk-$(HOST_WASI_SDK_VERSION)-x86_64-linux.tar.gz
HOST_WASI_SDK_SITE = https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-33
HOST_WASI_SDK_LICENSE = Apache-2.0

define HOST_WASI_SDK_BUILD_CMDS
endef

define HOST_WASI_SDK_INSTALL_CMDS
	mkdir -p $(HOST_DIR)/opt/wasi-sdk
	cp -a $(@D)/* $(HOST_DIR)/opt/wasi-sdk/
endef

pkgdir := $(dir $(lastword $(MAKEFILE_LIST)))
pkgname := $(notdir $(patsubst %/,%,$(pkgdir)))

$(info >>> reading wasi-sdk.mk)
$(info >>> wasi-sdk pkgdir before eval=$(pkgdir))
$(info >>> wasi-sdk pkgname before eval=$(pkgname))
$(info >>> wasi-sdk last_makefile=$(lastword $(MAKEFILE_LIST)))

$(eval $(host-generic-package))
