cmake_minimum_required(VERSION 3.10)
project(keystone_examples C CXX ASM)

# check if SDK has been built and KEYSTONE_SDK_DIR configuration variable exists
if (NOT DEFINED KEYSTONE_SDK_DIR)
  message(FATAL_ERROR "Please set KEYSTONE_SDK_DIR configuration variable to an installed SDK path")
endif()

set(ENV{KEYSTONE_SDK_DIR} ${KEYSTONE_SDK_DIR})

if (DEFINED PATH)
  set(ENV{PATH} ${PATH})
endif()

include(${KEYSTONE_SDK_DIR}/cmake/macros.cmake)
include(ExternalProject)
find_package(Git REQUIRED)

use_riscv_toolchain(${KEYSTONE_BITS})

# export include directory
include_directories(AFTER ${KEYSTONE_SDK_DIR}/include)

#
# Optional WASI/Wasm build support
#
option(KEYSTONE_BUILD_WASM "Build selected eapp sources as WASI wasm" OFF)

set(WASI_SDK_DIR "" CACHE PATH "Path to wasi-sdk installation")
set(WASI_TARGET "wasm32-wasip1" CACHE STRING "WASI target triple")

if(KEYSTONE_BUILD_WASM)
  if(NOT WASI_SDK_DIR)
    message(FATAL_ERROR "KEYSTONE_BUILD_WASM=ON requires -DWASI_SDK_DIR=/path/to/wasi-sdk")
  endif()

  set(WASI_CC "${WASI_SDK_DIR}/bin/clang" CACHE FILEPATH "WASI clang")
  set(WASI_SYSROOT "${WASI_SDK_DIR}/share/wasi-sysroot" CACHE PATH "WASI sysroot")

  if(NOT EXISTS "${WASI_CC}")
    message(FATAL_ERROR "WASI clang not found: ${WASI_CC}")
  endif()

  if(NOT EXISTS "${WASI_SYSROOT}")
    message(FATAL_ERROR "WASI sysroot not found: ${WASI_SYSROOT}")
  endif()

  set(XXD_EXECUTABLE "" CACHE FILEPATH "Path to host xxd executable")

  if(NOT XXD_EXECUTABLE)
    find_program(XXD_EXECUTABLE NAMES xxd REQUIRED)
  endif()

  if(NOT EXISTS "${XXD_EXECUTABLE}")
    message(FATAL_ERROR "xxd not found: ${XXD_EXECUTABLE}")
  endif()

  message(STATUS "XXD_EXECUTABLE=${XXD_EXECUTABLE}")

  #
  # Keystone eapp sources may refer to Keystone-specific functions.
  # For the first step, allow unresolved symbols so that wasm can be generated.
  # Later, these should be provided either as WASM imports or by a small stub layer.
  #
  option(KEYSTONE_WASM_ALLOW_UNDEFINED
    "Allow unresolved Keystone symbols when linking wasm"
    ON
  )

  set(KEYSTONE_WASI_COMMON_CFLAGS
    -I${KEYSTONE_SDK_DIR}/include
    -I${KEYSTONE_SDK_DIR}/include/app
    -I${KEYSTONE_SDK_DIR}/include/edge
    -I${KEYSTONE_SDK_DIR}/include/shared
    -I${CMAKE_SOURCE_DIR}
  )

  set(KEYSTONE_WASI_COMMON_LDFLAGS)

  if(KEYSTONE_WASM_ALLOW_UNDEFINED)
    list(APPEND KEYSTONE_WASI_COMMON_LDFLAGS
      -Wl,--allow-undefined
    )
  endif()

  find_path(WAMR_INCLUDE_DIR
    NAMES wasm_export.h
    PATHS
      "${CMAKE_SYSROOT}/usr/include/wasm-micro-runtime"
      "$ENV{STAGING_DIR}/usr/include/wasm-micro-runtime"
      "${CMAKE_SYSROOT}/usr/include"
      "$ENV{STAGING_DIR}/usr/include"
  )

  find_file(IWASM_STATIC_LIBRARY
    NAMES libiwasm.a
    PATHS
      "${CMAKE_SYSROOT}/usr/lib"
      "$ENV{STAGING_DIR}/usr/lib"
    NO_DEFAULT_PATH
  )

  if(NOT WAMR_INCLUDE_DIR)
    message(FATAL_ERROR "wasm_export.h was not found")
  endif()

  if(NOT IWASM_STATIC_LIBRARY)
    message(FATAL_ERROR "static libiwasm.a was not found")
  endif()

  message(STATUS "WAMR_INCLUDE_DIR=${WAMR_INCLUDE_DIR}")
  message(STATUS "IWASM_STATIC_LIBRARY=${IWASM_STATIC_LIBRARY}")

  function(add_keystone_wasm target_name output_name source_file)
    get_filename_component(src_abs "${source_file}" ABSOLUTE BASE_DIR "${CMAKE_SOURCE_DIR}")
    get_filename_component(src_dir "${src_abs}" DIRECTORY)
    get_filename_component(src_base "${src_abs}" NAME_WE)

    # Put generated WASM files under each example's build directory.
    file(RELATIVE_PATH src_rel "${CMAKE_SOURCE_DIR}" "${src_abs}")
    string(REPLACE "/" ";" src_rel_parts "${src_rel}")
    list(GET src_rel_parts 0 example_name)

    set(output_wasm_dir "${CMAKE_BINARY_DIR}/${example_name}/wasm")
    file(MAKE_DIRECTORY "${output_wasm_dir}")

    set(output_wasm "${output_wasm_dir}/${output_name}.wasm")
    set(output_wasm_c "${output_wasm_dir}/${src_base}_wasm.c")
    set(output_elf_target "${src_base}_wasm")

    add_custom_command(
      OUTPUT "${output_wasm}"
      COMMAND "${WASI_CC}"
              --target=${WASI_TARGET}
              --sysroot=${WASI_SYSROOT}
              -O2
              ${KEYSTONE_WASI_COMMON_CFLAGS}
              -I${src_dir}
              ${src_abs}
              -o "${output_wasm}"
              ${KEYSTONE_WASI_COMMON_LDFLAGS}
      DEPENDS "${src_abs}"
      COMMENT "Building ${output_name}.wasm from ${source_file}"
      VERBATIM
    )

    add_custom_command(
      OUTPUT "${output_wasm_c}"
      COMMAND "${XXD_EXECUTABLE}"
              -i
              -n embedded_wasm
              "${output_wasm}"
              "${output_wasm_c}"
      DEPENDS "${output_wasm}"
      COMMENT "Generating ${src_base}_wasm.c from ${output_name}.wasm"
      VERBATIM
    )

    add_custom_target(${target_name}
      DEPENDS "${output_wasm_c}"
    )

    add_executable(${output_elf_target}
      wasm_runner/embedded_wasm_main.c
      "${output_wasm_c}"
    )

    target_link_options(${output_elf_target}
      PRIVATE
        -static
    )

    target_include_directories(${output_elf_target}
      PRIVATE
        ${WAMR_INCLUDE_DIR}
    )

    target_link_libraries(${output_elf_target}
      PRIVATE
        ${IWASM_STATIC_LIBRARY}
        atomic
        m
        dl
        pthread
    )

    add_dependencies(${output_elf_target}
      ${target_name}
    )

    add_dependencies(examples
      ${output_elf_target}
    )

    install(TARGETS ${output_elf_target}
      RUNTIME DESTINATION share/keystone/examples
    )
  endfunction()

  find_program(MAKESELF_EXECUTABLE NAMES makeself REQUIRED)

  function(add_wasm_keystone_package
           package_target
           package_name
           example_dir
           host_target
           wasm_eapp_target
           eyrie_target)

    set(example_build_dir "${CMAKE_BINARY_DIR}/${example_dir}")
    set(package_dir "${example_build_dir}/pkg-${wasm_eapp_target}")
    set(package_output "${example_build_dir}/${package_name}")

    set(options_log "${example_build_dir}/.options_log")
    set(eyrie_rt "${example_build_dir}/eyrie-rt")
    set(loader_bin "${example_build_dir}/loader.bin")

    set(package_script
      "./${host_target}"
      "${wasm_eapp_target}"
      "eyrie-rt"
      "loader.bin"
    )

    add_custom_command(
      OUTPUT "${package_output}"
      COMMAND "${CMAKE_COMMAND}" -E rm -rf "${package_dir}"
      COMMAND "${CMAKE_COMMAND}" -E make_directory "${package_dir}"

      COMMAND "${CMAKE_COMMAND}" -E copy
              "$<TARGET_FILE:${host_target}>"
              "${package_dir}/${host_target}"

      COMMAND "${CMAKE_COMMAND}" -E copy
              "$<TARGET_FILE:${wasm_eapp_target}>"
              "${package_dir}/${wasm_eapp_target}"

      COMMAND "${CMAKE_COMMAND}" -E copy
              "${options_log}"
              "${package_dir}/.options_log"

      COMMAND "${CMAKE_COMMAND}" -E copy
              "${eyrie_rt}"
              "${package_dir}/eyrie-rt"

      COMMAND "${CMAKE_COMMAND}" -E copy
              "${loader_bin}"
              "${package_dir}/loader.bin"

      COMMAND "${MAKESELF_EXECUTABLE}" --noprogress
              "${package_dir}"
              "${package_output}"
              "Keystone Enclave Package"
              ${package_script}

      DEPENDS
        ${host_target}
        ${wasm_eapp_target}
        ${eyrie_target}

      WORKING_DIRECTORY "${example_build_dir}"
      COMMENT "Generating ${package_name}"
      VERBATIM
    )

    add_custom_target(${package_target}
      DEPENDS "${package_output}"
    )

    add_dependencies(examples
      ${package_target}
    )
  endfunction()

endif()

# set paths to the libraries
set(KEYSTONE_LIB_HOST ${KEYSTONE_SDK_DIR}/lib/libkeystone-host.a)
set(KEYSTONE_LIB_EDGE ${KEYSTONE_SDK_DIR}/lib/libkeystone-edge.a)
set(KEYSTONE_LIB_VERIFIER ${KEYSTONE_SDK_DIR}/lib/libkeystone-verifier.a)
set(KEYSTONE_LIB_EAPP ${KEYSTONE_SDK_DIR}/lib/libkeystone-eapp.a)

# create a phony target "examples"
add_custom_target("examples")

# add all examples below
add_subdirectory(hello)
add_subdirectory(hello-native)
add_subdirectory(attestation)
add_subdirectory(tests)
add_subdirectory(riv_attestation)
add_subdirectory(quote_check)
add_subdirectory(quote_check_esys)

if(KEYSTONE_BUILD_WASM)
  add_keystone_wasm(
    wasm_hello
    hello
    hello/eapp/hello.c
  )

  add_keystone_wasm(
    wasm_hello_native
    hello-native
    hello-native/eapp/eapp_native.c
  )

  add_keystone_wasm(
    wasm_attestor
    attestor
    attestation/eapp/attestor.c
  )

  add_wasm_keystone_package(
    hello_wasm-package
    hello_wasm.ke
    hello
    hello-runner
    hello_wasm
    hello-eyrie
  )
  
  add_wasm_keystone_package(
    eapp_native_wasm-package
    eapp_native_wasm.ke
    hello-native
    hello-native-runner
    eapp_native_wasm
    hello-native-eyrie
  )
  
  add_wasm_keystone_package(
    attestor_wasm-package
    attestor_wasm.ke
    attestation
    attestor-runner
    attestor_wasm
    attestor-eyrie
  )

  add_custom_target(wasm-examples)
  add_dependencies(wasm-examples
    wasm_hello
    wasm_hello_native
    wasm_attestor
    hello_wasm
    eapp_native_wasm
    attestor_wasm
    hello_wasm-package
    eapp_native_wasm-package
    attestor_wasm-package
  )

  add_dependencies(examples wasm-examples)
endif()
