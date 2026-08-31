# pcce-ta — PCCE TA (C -> wasm32-wasip1) を enclave内WAMRで実行するexample。
#
# 構成 (rivリポジトリ doc/design/wasm-ta.md / keystone-layout.md):
#   wasm/ta_main.c       TA本体。wasi-sdkで .wasm 化(段階2: 埋め込まず
#                        ビルド成果物として出力。ta-packで暗号化して配布)
#   eapp/runner_main.c   WAMR + "env" native imports + riv attesterループ
#   eapp/ta_loader.c     ta.encのhost経由チャンクロード
#   eapp/dev_key.c       sk_dev/pk_devの決定論的導出(sealing key由来)
#   host                 riv-attesterのhost(TCP中継+ta.enc給仕)を流用
#
# 前提: KEYSTONE_BUILD_WASM=ON かつ examples/riv-attester
# (rivリポジトリの scripts/build-keystone.sh がコピーを配置)が存在すること。
# 親のCMakeLists.txtが両条件を確認してから add_subdirectory する。
#
# runnerはTAの検証・復号にOpenSSL(buildroot stagingのlibcrypto.a)を
# 静的リンクする。検証・復号のみで乱数を使わないためRNG初期化は不要。
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

# TA: .wasm 生成(段階2: 埋め込まない。ta-packの入力になる成果物)

set(ta_wasm "${CMAKE_CURRENT_BINARY_DIR}/pcce_ta.wasm")

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

add_custom_target(${runner_bin}-ta-wasm ALL DEPENDS "${ta_wasm}")

# runner eapp: WAMR + TAローダ + riv attester(同一enclaveリンク)

# libkeystone-eapp.a はリンクしない(tiny-malloc.oが引き込まれ
# __malloc_start未解決になる)。syscallラッパは自前定義で持つ。
add_executable(${runner_bin}
  eapp/runner_main.c
  eapp/keystone_syscalls.c
  eapp/ta_loader.c
  eapp/dev_key.c
  ${riv_dir}/eapp/attester.c
  ${riv_dir}/common/src/riv_proto.c
  ${riv_dir}/common/src/riv_ta_verify.c)
target_link_options(${runner_bin} PRIVATE -static)
target_include_directories(${runner_bin}
  PRIVATE
    ${WAMR_INCLUDE_DIR}
    ${riv_dir}
    ${riv_dir}/common/include)
# crypto: buildroot sysroot(per-package staging)のlibcrypto.a。
# -staticなので静的側が選ばれる。
target_link_libraries(${runner_bin}
  PRIVATE
    ${IWASM_STATIC_LIBRARY}
    crypto
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
add_dependencies(examples ${runner_bin}-package ${runner_bin}-ta-wasm)
