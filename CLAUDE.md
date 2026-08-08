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

- `KEYSTONE_PLATFORM` — `generic` (QEMU), `cva6`, `hifive_unmatched`, `mpfs`. Default `generic`.
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

make run                    # boot QEMU (generic platform); login root / sifive; exit with ctrl-a x
KEYSTONE_DEBUG=y make run   # start QEMU halted with a gdb stub
make debug-connect          # attach cross-gdb (scripts/gdb/generic.cfg; pmp-dump/pmp-clear via scripts/gdb/pmp.py)
KEYSTONE_COMMAND="..." make call   # ssh a command into the running guest
```

Inside the guest: `modprobe keystone-driver`, then run a packaged enclave, e.g.
`/usr/share/keystone/examples/hello.ke`.

**`make run` on `generic` requires a swtpm socket at `/tmp/emulated_tpm/swtpm-sock`** — QEMU is launched
with `-tpmdev emulator` unconditionally (`mkutils/plat/generic/run.mk`) and will refuse to start without it.
The kernel cmdline also sets `ima_policy=tcb`.

### The content-hash package versioning gotcha

`mkutils/pkg-keystone.mk` sets each in-tree Keystone package's Buildroot *version* to a sha256 of its
source tree contents. Editing any file under `sdk/`, `runtime/`, `sm/`, `examples/`, `bootrom/`, or
`linux-keystone-driver/` therefore changes the package version, and Buildroot rebuilds it from scratch —
this is intentional, it is what makes in-tree edits actually take effect. The build prints a
`Stale build directory detected` warning when old-version directories linger; clear them with
`BUILDROOT_TARGET=<pkg>-dirclean make`. Do not hand-edit files inside `build-*/buildroot.build/build/`;
they are copies and get blown away.

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

`attestation/` is upstream. `riv_attestation/`, `quote_check/`, and `quote_check_esys/` are fork
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
3. **Push the branch and open a PR against `master`** (`gh pr create --base master`). Get **1 approving
   review** before merging. This one is a team agreement, **not** something GitHub enforces — see
   "What GitHub actually enforces" below — so it is on the author not to self-merge unreviewed.
4. **Do not merge, and do not approve, on the author's behalf.** Opening the PR is where the automated
   work stops; a human reviewer takes it from there.

### What GitHub actually enforces

The `Protect default branches` ruleset (id `17383480`, active, no bypass actors) covers
`~DEFAULT_BRANCH` — i.e. `master` only, *not* `dev`:

| | |
|---|---|
| Direct push to `master` | blocked — changes must arrive via PR |
| Force push / non-fast-forward | blocked |
| Branch deletion | blocked |
| **Required approving reviews** | **0** — a PR can be self-merged with no review |

So the platform guarantees *"it went through a PR"*, not *"someone reviewed it"*. The one-approval
rule lives in this document and in people's heads. Do not treat a mergeable PR as an approved one;
check the review state explicitly (`gh pr view --json reviewDecision,reviews`).

Classic branch protection is not configured; the ruleset is the only server-side control. If the team
later wants the approval requirement enforced, raise `required_approving_review_count` to 1 on that
ruleset and update the table above.

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
- If asked to merge a PR, check `reviewDecision` first. GitHub will happily merge an unreviewed PR
  here, so the check has to be done deliberately; if there is no approval, say so and stop.
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
