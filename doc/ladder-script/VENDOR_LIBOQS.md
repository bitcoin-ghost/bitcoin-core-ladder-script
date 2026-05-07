# Plan: vendor liboqs as a project-managed source tree

**Owner**: TBD
**Estimate**: 2-3 days focused
**Dependencies**: none (CMake scaffolding already in place)
**Status**: scaffolding committed; subtree import + build switchover pending

## Why

AUD-04 pinned liboqs to `0.10.1 EXACT` at the CMake `find_package`
layer plus a compile-time `static_assert` against `OQS_VERSION_TEXT`.
That closes the immediate consensus-split risk between nodes linking
different upstream `liboqs` versions, but leaves a residual: distros
can patch `0.10.1` with security fixes that change `OQS_SIG_verify`
behaviour at the malformed-input boundary. Two nodes both nominally
on `liboqs 0.10.1` could still fork if one of them is on a
distro-patched build.

Vendoring the source tree (libsecp256k1 pattern: `git subtree add`
into `src/liboqs/`, build via `add_subdirectory`) collapses that
residual to "the project controls every byte of the consensus
crypto". Operators build a known-identical liboqs no matter what
their distro does.

## Migration

The CMake scaffolding is already in place
(`src/rung/CMakeLists.txt`, `LADDER_VENDOR_LIBOQS` cache variable).
Setting it to `ON` with no source tree fails fast with an explicit
error pointing at this doc.

### Step 1: import the source tree

```sh
# From the repo root, pinning to the same version as the EXACT pin.
git subtree add --prefix=src/liboqs \
    https://github.com/open-quantum-safe/liboqs 0.10.1 --squash
```

This produces a single squash commit (~10-20 MB of source). Future
upstream merges are `git subtree pull --prefix=src/liboqs ... <new-version> --squash`.

### Step 2: trim what gets built

The vendored build is gated to the four schemes Ladder Script
consensus uses (FALCON-512, FALCON-1024, Dilithium3,
SPHINCS+-sha2-256f-simple). The scaffolding sets:

```cmake
set(OQS_MINIMAL_BUILD "SIG_falcon_512;SIG_falcon_1024;SIG_dilithium_3;SIG_sphincs_sha2_256f_simple"
    CACHE STRING "..." FORCE)
set(OQS_BUILD_ONLY_LIB ON CACHE BOOL "..." FORCE)
```

before `add_subdirectory(liboqs)`. liboqs respects these via its own
CMake option machinery — no source-tree edits required.

Verify after the subtree add by looking for these option definitions
in `src/liboqs/CMakeLists.txt`.

### Step 3: switch the build over

```sh
cmake -DLADDER_VENDOR_LIBOQS=ON -B build
cmake --build build -j2 --target bitcoin_rung
cmake --build build -j2 --target test_bitcoin
build/bin/test_bitcoin --run_test=rung_tests
build/test/functional/feature_rung_tx.py
build/test/functional/feature_rung_pq_batch.py
build/test/functional/feature_rung_pq_batch_stress.py
build/test/functional/feature_qabi.py
build/test/functional/feature_qabi_size.py
```

All must pass. The PQ_BATCH stress test in particular catches any
amortisation regression — pre/post-vendor numbers should be within
single-digit percent.

### Step 4: cross-platform CI

Linux x86_64 (the default dev env): expected to work out of the box.

macOS arm64: liboqs has known AVX2 detection caveats; test the build
without `OQS_USE_AVX2` if it fails. Keep AVX2 OFF for the consensus
build to ensure determinism across CPU generations.

Windows: liboqs's MSVC support is improving but historically rougher
than POSIX. Likely needs an extra `OQS_USE_OPENSSL=OFF` flag.

The CI matrix should grow at least one job per platform that
explicitly builds with `LADDER_VENDOR_LIBOQS=ON` and runs the rung
test surface. The system-install path can stay in CI for development
ergonomics but the consensus-binding build is the vendored one.

### Step 5: flip the default

Once Step 4 is green across the matrix, change
`option(LADDER_VENDOR_LIBOQS ... OFF)` to `... ON` in
`src/rung/CMakeLists.txt`. The system-install path becomes opt-out
for local development convenience; release builds always vendor.

### Step 6: BIP draft

Update §FAQ 12 and §Build/Operations in `doc/ladder-script/BIP-XXXX.md`
to mention that the vendored source tree at `src/liboqs/` is the
canonical consensus implementation and that distro packages of
liboqs are explicitly not part of the consensus surface for vendored
builds.

## Caveats / known unknowns

- **Build time**: vendoring adds ~30-60s to a clean build on the
  current 16-core dev box (the four trimmed algorithms compile fast
  individually; liboqs's CMake setup itself isn't slow). Acceptable.
- **`OQS_USE_OPENSSL`**: liboqs can optionally use OpenSSL for some
  primitives. We want this OFF for the consensus build so the
  cryptographic surface stays minimal. The scaffolding doesn't yet
  set this — verify and add to the FORCE list if needed during Step 3.
- **`OQS_DIST_BUILD`**: portable assembly. Should stay default for
  determinism; verify on each CI platform.
- **secp256k1 pattern parity**: libsecp256k1 lives at `src/secp256k1/`
  and is updated via `git subtree pull`. liboqs follows the same
  pattern. Commits that update the subtree should have a clear
  "Update liboqs subtree to 0.X.Y" subject line so reviewers can
  trace the consensus-crypto bump.

## Why this isn't done yet

Vendoring is a clean operation but the post-import work (Step 4
cross-platform CI) is the time-consuming part. The audit closed the
immediate consensus-split risk via the EXACT pin + static_assert; the
vendoring is a long-term hardening that warrants its own focused
review — particularly because changing the consensus crypto build
machinery is itself a hard fork.
