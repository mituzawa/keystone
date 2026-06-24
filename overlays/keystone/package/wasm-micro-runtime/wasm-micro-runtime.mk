################################################################################
#
# wasm-micro-runtime
#
################################################################################

# Use a fixed WAMR release tag.
# Latest release seen on GitHub is WAMR-2.4.4, but you may pin another tag
# or a specific commit hash for reproducible builds.
WASM_MICRO_RUNTIME_VERSION = WAMR-2.4.4
WASM_MICRO_RUNTIME_VERSION_NUMBER = 2.4.4
WASM_MICRO_RUNTIME_SITE = https://github.com/bytecodealliance/wasm-micro-runtime.git
WASM_MICRO_RUNTIME_SITE_METHOD = git

WASM_MICRO_RUNTIME_LICENSE = Apache-2.0
WASM_MICRO_RUNTIME_LICENSE_FILES = LICENSE

# The CMakeLists.txt file for iwasm is located in this directory.
WASM_MICRO_RUNTIME_SUBDIR = product-mini/platforms/linux

# Use an out-of-source build directory.
WASM_MICRO_RUNTIME_SUPPORTS_IN_SOURCE_BUILD = NO

# Install headers and libraries into the staging directory so that
# other Buildroot packages can build against libiwasm.
WASM_MICRO_RUNTIME_INSTALL_STAGING = YES

# Build iwasm for the target system.
#
# For the first step, keep the configuration simple:
#   - interpreter enabled
#   - JIT/AOT disabled
#   - WASI libc enabled
#   - pthread/shared-memory/SIMD disabled
#
# This should be easier to cross-build for the Keystone target rootfs.
WASM_MICRO_RUNTIME_CONF_OPTS += \
	-DWAMR_BUILD_PLATFORM=linux \
	-DWAMR_BUILD_INTERP=1 \
	-DWAMR_BUILD_FAST_INTERP=1 \
	-DWAMR_BUILD_JIT=0 \
	-DWAMR_BUILD_FAST_JIT=0 \
	-DWAMR_BUILD_AOT=0 \
	-DWAMR_BUILD_LIBC_WASI=1 \
	-DWAMR_BUILD_LIB_PTHREAD=0 \
	-DWAMR_BUILD_SHARED_MEMORY=0 \
	-DWAMR_BUILD_SIMD=0 \
	-DWAMR_BUILD_SIMDE=0 \
	-DWAMR_DISABLE_HW_BOUND_CHECK=1 \
	-DWAMR_DISABLE_STACK_HW_BOUND_CHECK=1 \
	-DBUILD_SHARED_LIBS=OFF \
	-DCMAKE_C_STANDARD_LIBRARIES="-latomic" \
	-DCMAKE_CXX_STANDARD_LIBRARIES="-latomic"

# Install libiwasm development files into the staging directory.
define WASM_MICRO_RUNTIME_INSTALL_STAGING_CMDS
	mkdir -p $(STAGING_DIR)/usr/include/wasm-micro-runtime
	mkdir -p $(STAGING_DIR)/usr/lib

	$(INSTALL) -m 0644 \
		$(@D)/core/iwasm/include/*.h \
		$(STAGING_DIR)/usr/include/wasm-micro-runtime/

	$(INSTALL) -D -m 0644 \
		$(@D)/product-mini/platforms/linux/buildroot-build/libiwasm.a \
		$(STAGING_DIR)/usr/lib/libiwasm.a
endef

# Install iwasm into the target root filesystem.
define WASM_MICRO_RUNTIME_INSTALL_TARGET_CMDS
	mkdir -p $(TARGET_DIR)/usr/bin

	$(INSTALL) -D -m 0755 \
		$(@D)/product-mini/platforms/linux/buildroot-build/iwasm-$(WASM_MICRO_RUNTIME_VERSION_NUMBER) \
		$(TARGET_DIR)/usr/bin/iwasm
endef

$(eval $(cmake-package))
