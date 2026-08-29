# pcce-ta — PCCE TA (C -> wasm32-wasip1) を enclave内WAMRで実行するexample。
#
# 構成 (rivリポジトリ doc/design/wasm-ta.md / keystone-layout.md):
#   wasm/ta_main.c       TA本体。wasi-sdkで .wasm 化し xxd で埋め込む(段階1)
#   eapp/runner_main.c   WAMR + "env" native imports + riv attesterループ
#   host                 riv-attesterのhost(TCP中継)を流用
#
# 前提: KEYSTONE_BUILD_WASM=ON かつ examples/riv-attester
# (rivリポジトリの scripts/build-keystone.sh がコピーを配置)が存在すること。
# 親のCMakeLists.txtが両条件を確認してから add_subdirectory する。
#
# TAは --allow-undefined なしでリンクする(importはimport_module属性で明示。
# 漏れがあればwasi-sdkのリンクエラーになる)。

set(runner_bin pcce-ta-runner)
set(host_bin pcce-ta-host)
set(package_name "pcce-ta.ke")
set(package_script "./pcce-ta-host pcce-ta-runner eyrie-rt loader.bin")
# WAMR runnerはglibc静的リンクのため io_syscall 等が必須 (helloと同じ)
set(eyrie_plugins "io_syscall linux_syscall env_setup")

set(riv_dir "${CMAKE_SOURCE_DIR}/riv-attester")

# TA: .wasm 生成 → xxd埋め込みCソース生成

set(ta_wasm "${CMAKE_CURRENT_BINARY_DIR}/pcce_ta.wasm")
set(ta_wasm_c "${CMAKE_CURRENT_BINARY_DIR}/pcce_ta_wasm.c")

add_custom_command(
  OUTPUT "${ta_wasm}"
  COMMAND "${WASI_CC}"
          --target=${WASI_TARGET}
          --sysroot=${WASI_SYSROOT}
          -O2
          "${CMAKE_CURRENT_SOURCE_DIR}/wasm/ta_main.c"
          -o "${ta_wasm}"
  DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/wasm/ta_main.c"
  COMMENT "Building pcce_ta.wasm"
  VERBATIM
)

add_custom_command(
  OUTPUT "${ta_wasm_c}"
  COMMAND "${XXD_EXECUTABLE}" -i -n embedded_wasm "${ta_wasm}" "${ta_wasm_c}"
  DEPENDS "${ta_wasm}"
  COMMENT "Generating pcce_ta_wasm.c"
  VERBATIM
)

# runner eapp: WAMR + 埋め込みTA + riv attester(同一enclaveリンク)

# libkeystone-eapp.a はリンクしない(tiny-malloc.oが引き込まれ
# __malloc_start未解決になる)。syscallラッパは自前定義で持つ。
add_executable(${runner_bin}
  eapp/runner_main.c
  eapp/keystone_syscalls.c
  "${ta_wasm_c}"
  ${riv_dir}/eapp/attester.c
  ${riv_dir}/common/src/riv_proto.c)
target_link_options(${runner_bin} PRIVATE -static)
target_include_directories(${runner_bin}
  PRIVATE
    ${WAMR_INCLUDE_DIR}
    ${riv_dir}
    ${riv_dir}/common/include)
target_link_libraries(${runner_bin}
  PRIVATE
    ${IWASM_STATIC_LIBRARY}
    atomic
    m
    dl
    pthread)

# host: riv-attesterのhostを流用(パス指定のみ変える)

add_executable(${host_bin}
  ${riv_dir}/host/host.cpp
  ${riv_dir}/common/src/riv_proto.c
  ${riv_dir}/common/src/riv_transport.c)
target_link_libraries(${host_bin} ${KEYSTONE_LIB_HOST} ${KEYSTONE_LIB_EDGE})
set_target_properties(${host_bin}
  PROPERTIES CXX_STANDARD 11 CXX_STANDARD_REQUIRED YES CXX_EXTENSIONS NO)
target_include_directories(${host_bin}
  PUBLIC ${KEYSTONE_SDK_DIR}/include/host
  PUBLIC ${KEYSTONE_SDK_DIR}/include/edge
  PUBLIC ${riv_dir}/common/include)

# eyrie runtime と .ke パッケージ

set(eyrie_files_to_copy .options_log eyrie-rt loader.bin)
add_eyrie_runtime(${runner_bin}-eyrie
  ${eyrie_plugins}
  ${eyrie_files_to_copy})

add_keystone_package(${runner_bin}-package
  ${package_name}
  ${package_script}
  ${eyrie_files_to_copy} ${runner_bin} ${host_bin})

add_dependencies(${runner_bin}-package ${runner_bin}-eyrie)
add_dependencies(examples ${runner_bin}-package)
