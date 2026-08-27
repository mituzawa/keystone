# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Keystone: a TEE (secure enclave) framework for RISC-V. This is a **fork** of `keystone-enclave/keystone`
that adds WebAssembly enclave applications (WAMR + wasi-sdk), TPM-backed quote/attestation examples,
and IMA measurement. The `buildroot` submodule points at `github.com/mituzawa/buildroot` (fork), not upstream.

## Build system

The top-level `Makefile` is the only supported entry point. It is a thin frontend that configures and
drives **Buildroot** with `overlays/keystone` as a `BR2_EXTERNAL` tree. Everything — toolchain, kernel,
OpenSBI+SM, driver, SDK, runtime, examples, QEMU — is built as Buildroot packages.

`CMakeLists.txt` at the repo root is **vestigial** from the pre-2023 build system (it references
`scripts/run-qemu.sh.in`, which no longer exists). Do not use it or extend it. The per-component
`CMakeLists.txt` files (`sdk/`, `runtime/`, `examples/`) *are* live — Buildroot invokes them.

Configuration is passed as environment variables (see `docs/source/Getting-Started/QEMU-Compile-Sources.rst`):

- `KEYSTONE_PLATFORM` — `generic` (QEMU), `cva6`, `hifive_unmatched`, `mpfs`,
  `hifive_premier_p550` (64-bit only). Default `generic`.
- `KEYSTONE_BITS` — `64` or `32`. Default `64`.
- `BUILDROOT_TARGET` — Buildroot subtarget to build instead of `all`.
- `KEYSTONE_LOG_LEVEL` — 0=debug … 4=fatal (see `mkutils/log.mk`).

Output lands in `build-$(KEYSTONE_PLATFORM)$(KEYSTONE_BITS)/`, with the Buildroot tree under
`buildroot.build/` and the full (very verbose) log at `build.log`. Only lines matching
`scripts/grep.patterns` are echoed to stdout — read `build.log` to debug failures.

### Commands

```bash
git submodule update --init --recursive --depth 1   # or ./fast-setup.sh

make -j$(nproc)                                     # build everything
KEYSTONE_PLATFORM=mpfs make -j$(nproc)              # build for another platform
BUILDROOT_TARGET=keystone-sm make -j$(nproc)        # build one Buildroot package
BUILDROOT_TARGET=keystone-runtime-dirclean make     # clean one package

make buildroot-configure    # menuconfig, then writes back overlays/keystone/configs/<defconfig>
make linux-configure        # linux-menuconfig, then writes back overlays/keystone/configs/linux*-defconfig
                            # ^ both are development helpers — a plain `make` never opens a menu

make run                    # boot QEMU (generic platform); login root / sifive; exit with ctrl-a x
KEYSTONE_DEBUG=y make run   # start QEMU halted with a gdb stub
make debug-connect          # attach cross-gdb (scripts/gdb/generic.cfg; pmp-dump/pmp-clear via scripts/gdb/pmp.py)
KEYSTONE_COMMAND="..." make call   # ssh a command into the running guest
```

Inside the guest: `modprobe keystone-driver`, then run a packaged enclave, e.g.
`/usr/share/keystone/examples/hello.ke`.

**`make run` on `generic` requires a swtpm socket at `/tmp/emulated_tpm/swtpm-sock`** — QEMU is launched
with `-tpmdev emulator` unconditionally (`mkutils/plat/generic/run.mk`) and will refuse to start without it.
The TPM frontend (`tcg,tpm-tis-mmio` at `0x10101000`) is not on the QEMU command line — the buildroot
fork's `package/qemu/0005-riscv-virt-add-tpm-support.patch` auto-instantiates it whenever a tpmdev
backend exists and emits the `/soc/tpm@10101000` FDT node.

### Measured boot on `generic`

The generic platform boots `-bios fw_payload.elf` (OpenSBI+SM with **U-Boot 2024.01** as `FW_PAYLOAD`),
not `fw_jump` + `-kernel`. U-Boot loads `/boot/Image` from the rootfs via extlinux and, before booting
it, extends TPM PCRs (`CONFIG_MEASURED_BOOT`): PCR8 ← kernel, PCR9 ← initrd, PCR1 ← bootargs,
PCR0 ← DTB + CRTM version + separators. IMA then extends PCR10 at runtime (`ima_policy=tcb`).

- The kernel cmdline lives in `overlays/keystone/board/qemu/generic/extlinux.conf` (installed to
  `/boot/extlinux/` by `post-build.sh` from the same directory), **not** in `run.mk`.
- U-Boot's TPM driver + measured boot come from the Kconfig fragment
  `overlays/keystone/board/qemu/generic/uboot-tpm.config`. Its `CONFIG_PREBOOT` grafts
  `tpm_event_log_addr/size` into the TPM DT node — **without an event-log buffer U-Boot measures
  nothing and does not complain** (`bootm_measure()`'s return value is ignored). So when touching this
  area, verify with PCR values (`/sys/class/tpm/tpm0/pcr-sha256/8` must be non-zero), never with
  "it boots".
- The bootrom (CRTM) still measures only `0x80000000..0x801ff000` (OpenSBI+SM) into the sanctum
  parameters; U-Boot sits at `+0x200000`, *outside* that window, and is itself unmeasured — a known
  gap. PCR0 varies per boot because QEMU injects a fresh `rng-seed` into `/chosen` (drop
  `CONFIG_MEASURE_DEVICETREE` if a stable PCR0 is ever needed).
- The attestation/quote examples embed the SM image the bootrom measures: `keystone-examples.mk`
  passes `-Dfw_bin=fw_payload.bin` for `generic` (and cva6). **The embedded copy goes stale**: Buildroot
  dependencies only order builds, so rebuilding `opensbi`/`uboot`/`keystone-sm` (a `-dirclean`, a U-Boot
  config change, or any `sm/` source edit) produces a new `fw_payload.bin` without repackaging the
  examples — the `.ke` files keep the old firmware and `attestor.ke`/`quote*.ke` then fail with
  `Either the enclave hash or the SM hash (or both) does not match`. The failing side is the *expected*
  SM hash (computed from the packaged copy), not the measurement. Fix:
  `BUILDROOT_TARGET=keystone-examples-dirclean make`. When debugging such a mismatch, compare
  `md5sum images/fw_payload.bin build/keystone-examples-*/attestation/pkg/fw_payload.bin` first.

### HiFive Premier P550 (`hifive_premier_p550`)

Fork-added hardware platform (ESWIN EIC7700X, 4× SiFive P550). Unlike the other platforms it builds
everything from the **eswincomputing vendor forks**, pinned by commit in
`overlays/keystone/configs/riscv64_hifive_premier_p550_defconfig`: OpenSBI `opensbi-1.3-EIC7X`
(the repo's first 1.3-based platform — OpenSBI 1.3 needs `Kconfig` + `configs/defconfig` in the
platform dir, which is why `sm/plat/eswin/eic770x/` carries them), U-Boot `u-boot-2024.01-EIC7X`,
Linux `linux-6.6.18-EIC7X` (vendor in-tree `eic7700` defconfig + a Keystone CMA fragment, so
`make linux-configure` does not work here). The SM rides the vendor's dedicated
`platform/eswin/eic770x` OpenSBI platform; `sm_init` is hooked in by a board patch
(`overlays/keystone/board/eswin/hifive-premier-p550/patches/opensbi/`), and the memory layout
(`FW_TEXT_START=0x80000000`, payload at `+0x200000`) is hardcoded in `sm/plat/eswin/eic770x/config.mk`
together with the `-DBR2_CHIPLET_1 -DBR2_CHIPLET_1_DIE0_AVAILABLE` macros that select the 4-hart
single-die topology — dropping those silently builds an 8-hart dual-die configuration.

The shared `overlays/keystone/patches/` dir is **not** applied on this platform (the basename patch
doesn't apply to the vendor fork; the secure-boot ldS patch is unused). There is no root of trust
yet: the P550 boot chain (SCPU mask ROM → QSPI bootchain → `fw_payload`) has no patchable stage
before the SM, so `sm_copy_key()` zeroes all keys (mpfs-style) and attestation cannot verify on
hardware. The build stops at `images/fw_payload.bin` + `sdcard.img` (single GPT rootfs partition —
firmware lives in QSPI); packaging the QSPI bootchain (`nsign`, ddr/second-boot blobs from
`sifive/hifive-premier-p550-tools`) and flashing (`es_burn`) are manual follow-up steps.

### The content-hash package versioning gotcha

`mkutils/pkg-keystone.mk` sets each in-tree Keystone package's Buildroot *version* to a sha256 of its
source tree contents. Editing any file under `sdk/`, `runtime/`, `sm/`, `examples/`, `bootrom/`, or
`linux-keystone-driver/` therefore changes the package version, and Buildroot rebuilds it from scratch —
this is intentional, it is what makes in-tree edits actually take effect. The build prints a
`Stale build directory detected` warning when old-version directories linger; clear them with
`BUILDROOT_TARGET=<pkg>-dirclean make`. Do not hand-edit files inside `build-*/buildroot.build/build/`;
they are copies and get blown away.

### Who runs `*-configure`, and why the defconfigs drift

Nobody needs to run the configure targets to build. `all` → `buildroot` depends only on
`$(BUILDROOT_BUILDDIR)/.config`, whose rule applies the committed defconfig non-interactively
(`Makefile:70-74`). `buildroot-configure` and `linux-configure` are separate `.PHONY` targets that
nothing in the build path invokes — **run them only when you actually intend to change the
configuration.** Everyone else just runs `make` and inherits the settings from the committed defconfigs.

Both helpers write back into `overlays/keystone/configs/`, and the write-back is lossy in ways that
look like somebody's hand edit but are purely mechanical:

- `savedefconfig` emits only symbols that differ from their Kconfig default, so anything matching the
  default is silently dropped. Buildroot 2023.02.2 declares `default BR2_TOOLCHAIN_BUILDROOT_GLIBC`
  (`toolchain/toolchain-buildroot/Config.in`), so that line vanishes from any defconfig round-tripped
  through the target.
- `Makefile:73` appends a machine-specific absolute `BR2_ROOTFS_OVERLAY` to `.config`, and
  `Makefile:107` then deletes *every* `BR2_ROOTFS_OVERLAY` line from the defconfig to keep that path out
  of the repository — including a hand-written placeholder.

The consequence is that a defconfig still carrying either line is not a fixed point: entering and
exiting menuconfig without touching anything leaves it modified. `riscv64_generic_defconfig` has been
normalised so a no-op round trip is byte-identical, matching `cva6`, `mpfs`, and `hifive_unmatched`.
**Do not re-add `BR2_TOOLCHAIN_BUILDROOT_GLIBC=y` or `BR2_ROOTFS_OVERLAY` to it** — glibc is still
selected as the Kconfig default, and the overlay path is supplied at build time. `riscv64_firesim`,
`riscv64_sifive`, and `riscv32_generic` still carry the old lines; they are not on the supported
platform list (`Makefile:27`) so nobody has run the target against them.

### A changed Buildroot defconfig does not reach an existing build tree

The two generated configs behave differently, and the Buildroot one will quietly ignore what you pulled:

| changed file | picked up by a plain `make`? |
|---|---|
| `configs/linux*-defconfig` | **yes** — `buildroot/package/pkg-kconfig.mk:159` makes the kernel's `.stamp_dotconfig` depend on `LINUX_KCONFIG_FILE`, so Buildroot reconfigures |
| `configs/riscv*_defconfig` | **no** — `Makefile:70` depends on the build *directory*, not on the defconfig, so an existing `build-*/buildroot.build/.config` is never regenerated |

So after pulling a commit that touches a Buildroot defconfig, delete the build directory
(`rm -rf build-$(KEYSTONE_PLATFORM)$(KEYSTONE_BITS)`) or the change has no effect — the build will
succeed with the old settings. Buildroot does not support incremental rebuilds across configuration
changes anyway. Neither `.config` is tracked; `.gitignore`'s `build*/` covers both.

## Tests

```bash
# Eyrie runtime unit tests (host-native, cmocka; needs runtime/test/cmocka submodule)
cd runtime && mkdir -p obj/test && cd obj/test && cmake ../../test && make && ctest -VV
ctest -R test_merkle -VV                             # single test

# Runtime build-matrix check (after a full build exists)
./scripts/ci/build-runtime.sh $PWD/runtime generic 64 -DPAGING=on -DPAGE_CRYPTO=on

# End-to-end QEMU system test
scripts/ci/plat/generic/test.sh                      # needs CMD_LOGFILE, LOGFILE, KEYSTONE_BITS set
diff -wB cmd.log scripts/ci/plat/generic/expected.log # must be empty
```

CI (`.github/workflows/main.yml`) builds the {generic, cva6, hifive_unmatched, mpfs} × {32, 64} matrix,
then runs the runtime unit tests, the runtime build matrix (`build-runtime.yml`), and per-platform
system tests (`test-system.yml`). `runtime/` is additionally format-checked: CI runs `git clang-format`
from inside `runtime/` and fails unless it reports no modifications, so run that before submitting
changes there. (`runtime/README.md` mentions `make format`/`make test`; there is no `runtime/Makefile`
any more — those instructions are stale.)

`tests/test-qemu.expected.log` is a leftover from the old CMake flow; the live expectation file is
`scripts/ci/plat/<platform>/expected.log`.

## Architecture

Boot chain, in order — each stage measures/launches the next:

1. **`bootrom/`** — simulated silicon root of trust. Generates the device keypair, measures the SM,
   signs the SM's attestation certificate (`test_dev_key.h` = insecure test keys).
2. **`sm/`** — the Security Monitor, built as an **out-of-tree OpenSBI platform** (`sm/plat/<platform>`,
   wired up by `overlays/keystone/boot/keystone-sm/keystone-sm.mk`). Runs in M-mode, owns PMP-based
   memory isolation (`pmp.c`), enclave lifecycle (`enclave.c`), attestation (`attest.c`), and exposes
   everything to S-mode as SBI calls (`sm-sbi.c`; spec in `sm/spec/`). On `mpfs` it is embedded in HSS
   instead of OpenSBI.
3. **`linux-keystone-driver/`** — Linux kernel module providing `/dev/keystone_enclave`; translates
   host ioctls into SM SBI calls.
4. **`sdk/`** — libraries linked into the two halves of an application:
   `libkeystone-host` (untrusted host, C++, `include/host/Enclave.hpp`), `libkeystone-eapp`
   (in-enclave), `libkeystone-edge` (edge calls across the boundary), `libkeystone-verifier`
   (attestation report checking). `include/shared/` holds the ABI headers shared by *all* layers —
   changing them ripples through SM, driver, runtime, and apps.
5. **`runtime/`** — the **Eyrie** runtime, an S-mode supervisor that lives inside the enclave.
   `loader-binary/` is a physically-addressed first-stage loader; `sys/` is boot/trap handling;
   `mm/` is paging; `call/` implements syscall proxying to the host. Feature-gated at compile time by
   CMake `rt_option`s → `-DUSE_<NAME>`: `PAGING`, `PAGE_CRYPTO`, `PAGE_HASH`, `LINUX_SYSCALL`,
   `IO_SYSCALL`, `NET_SYSCALL`, `ENV_SETUP`, `INTERNAL_STRACE`, `DEBUG`. Each example picks its own
   set via `eyrie_plugins`, so Eyrie is rebuilt per-example by `add_eyrie_runtime` in `sdk/macros.cmake`.
6. **`examples/`** — each subdirectory is one enclave app: an `eapp/` (enclave side), a `host/`
   (untrusted side), a chosen `eyrie_plugins` string, and an `add_keystone_package` call that bundles
   host binary + eapp + `eyrie-rt` + `loader.bin` into a self-extracting `.ke` via `makeself`.
   Only `*.ke` files get installed into the target rootfs (`/usr/share/keystone/examples`).

### Buildroot overlay layout (`overlays/keystone/`)

- `configs/` — Buildroot defconfigs (`riscv{32,64}_<platform>_defconfig`) and Linux defconfigs.
  These are the canonical configs; `make buildroot-configure` / `make linux-configure` write back here.
- `boot/` — `keystone-bootrom`, `keystone-sm`, `hss`. These packages *inject* into OpenSBI/HSS builds
  rather than producing standalone output (see how `keystone-sm.mk` appends to `OPENSBI_MAKE_ENV`).
- `package/` — `keystone-sdk` (host package), `keystone-driver`, `keystone-runtime` (source-only,
  consumed by examples), `keystone-examples`, plus `wasm-micro-runtime` and `wasi-sdk`.
- `external.mk` — includes package `.mk`s and holds platform-specific hooks (U-Boot patching for
  hifive_unmatched, device-tree/payload plumbing for mpfs). Note it must include
  `wasm-micro-runtime.mk` *before* the mkutils-based Keystone packages, because `pkg-keystone.mk`
  derives `pkgdir`/`pkgname` from the position in `MAKEFILE_LIST`.
- `patches/` — patches applied to `linux`, `opensbi`, `qemu`.

### WebAssembly enclave apps (fork-specific)

Enabled by `-DKEYSTONE_BUILD_WASM=ON` (set unconditionally in `keystone-examples.mk`). The flow, all in
`examples/CMakeLists.txt`:

`eapp C source` → wasi-sdk clang (`wasm32-wasip1`) → `.wasm` → `xxd -i` → C byte array →
linked with `examples/wasm_runner/embedded_wasm_main.c` and static `libiwasm.a` (WAMR, interpreter-only,
no JIT/AOT) → a normal RISC-V enclave binary that interprets the embedded module at runtime →
packaged as `<name>_wasm.ke`.

WAMR is built for the target with staging install (`libiwasm.a` + headers under
`/usr/include/wasm-micro-runtime`); wasi-sdk is a *host* package unpacked into `$(HOST_DIR)/opt/wasi-sdk`.

### Attestation examples

`attestation/` is upstream. `quote_check/` and `quote_check_esys/` are fork
additions; the `quote_check*` hosts link against `tpm2-tss` (`tss2-tctildr`/`tss2-sys`/`tss2-rc`/`tss2-mu`)
and combine a Keystone enclave report with a TPM quote, which is why `make run` needs the emulated TPM.

## Git workflow — MANDATORY

Five people share this repository. **Every change goes through a feature branch and a pull request.
There are no exceptions, and this applies to changes of any size, including one-line fixes,
documentation, and config tweaks.**

1. **Never commit directly to `master`.** Before making any edit, check the current branch. If it is
   `master`, create a feature branch first — including when there are already uncommitted changes in
   the working tree (`git switch -c <branch>` carries them over).
2. **Branch name: `feature/<member>/<topic>`.** `<member>` is one of the five team members —
   `mit`, `tani`, `ono`, `sa`, `sho` — and `<topic>` describes the work. Existing examples:
   `feature/mit/wasm-micro-runtime`, `feature/tani/quote-program`, `feature/sa/ima-config`.
   Both kebab-case and snake_case topics appear in the history; either is fine.
3. **Push the branch and open a PR against `master`** (`gh pr create --base master`). What is required
   is that the change *arrives as a PR* rather than a direct push. **An approving review is not
   required** — review is welcome, and the author may merge their own PR without one.
4. **Do not merge, and do not approve, on the author's behalf.** Opening the PR is where the automated
   work stops; merging is a deliberate decision for a person to make.

### What GitHub actually enforces

The `Protect default branches` ruleset (id `17383480`, active, no bypass actors) covers
`~DEFAULT_BRANCH` — i.e. `master` only, *not* `dev`:

| | |
|---|---|
| Direct push to `master` | blocked — changes must arrive via PR |
| Force push / non-fast-forward | blocked |
| Branch deletion | blocked |
| **Required approving reviews** | **0** — a PR can be self-merged with no review |

The platform therefore guarantees *"it went through a PR"*, not *"someone reviewed it"* — and that is
the intended policy, not a gap. An unreviewed PR is legitimately mergeable by its author, so a missing
approval is not a reason to hold a merge. `gh pr view --json reviewDecision,reviews` still tells you
what review a PR actually got, which is worth reporting even though nothing depends on it.

Classic branch protection is not configured; the ruleset is the only server-side control. The zero
approval requirement is deliberate, so this document and the server agree. If the team ever wants
review enforced, raise `required_approving_review_count` on that ruleset and update the table above —
rather than documenting a stricter rule here than the server applies.

### Enforcement

`scripts/git-hooks/` holds hooks that enforce the above. **They are not active until each person
enables them once per clone:**

```bash
git config core.hooksPath scripts/git-hooks
```

- `pre-commit` — refuses commits on `master`/`main`/`dev`, and refuses branch names that are not
  `feature/<member>/<topic>` with `<member>` on the roster. The roster lives in the `MEMBERS`
  variable at the top of the hook; **when someone joins or leaves the team, edit that one line.**
  Because the check is a whitelist rather than a pattern, it also catches typos and casing slips
  (`feature/mitt/...`, `feature/Mit/...`) and suggests the intended name.
- `pre-push` — refuses pushes that would update `master`/`main`/`dev` directly.

If a checkout is behaving as if the rules don't exist, `git config core.hooksPath` is the first thing
to check. Both hooks can be bypassed with `--no-verify`; that is a deliberate escape hatch for
exceptional situations, not a normal step.

Claude Code specifics:

- Commit and push only when explicitly asked — but when asked while on `master`, branch first and say so.
- If asked to merge a PR, merging an unreviewed one is fine — that is the policy here, so a missing
  approval is not a reason to stop. Merge only when asked, and never approve on the author's behalf.
- Never reach for `--no-verify`, a force push to `master`, or `core.hooksPath` unset to get around a
  blocked operation. If a hook fires, report it and let the user decide.

## Conventions

- `sdk/`, `runtime/`, and `sm/` were previously separate repos and still carry their own
  `README.md`/`LICENSE` and build docs describing standalone builds — those instructions are stale;
  build through the top-level Makefile.
- `runtime/` builds with `-Wall -Werror -mcmodel=medany -std=c11`; `medany` is required because the
  loader runs in physical addressing and cannot use a GOT.
- `CONTRIBUTING.md` describes an upstream `dev` → `master` flow with per-submodule PRs. That is
  inherited from `keystone-enclave/keystone` and does **not** match this fork, which is a monorepo
  with the `feature/<member>/<topic>` → `master` flow above.
