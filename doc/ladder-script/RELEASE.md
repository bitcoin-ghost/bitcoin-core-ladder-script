# Release process

Releases are tagged `v30.0-ladder-0.N` (see [CHANGELOG.md](CHANGELOG.md)). This is
the runbook for cutting one.

## 1. Tag

```
git tag -s v30.0-ladder-0.N -m "Ladder Script 0.N"
git push origin v30.0-ladder-0.N
```

Pushing a `v*.*.*` tag triggers `.github/workflows/release.yml`, which builds the
Linux/macOS/Windows artifacts, computes `SHA256SUMS`, and PGP-signs it.

## 2. Signing (configured ✓)

The release job signs `SHA256SUMS` with the repo secrets `GPG_PRIVATE_KEY` /
`GPG_PASSPHRASE` (set 2026-04-26). **Tagged builds fail closed** if the key is
absent — there is no path to a silently-unsigned release. The signing key
fingerprint published on `ladder-script.org/get-started.html#download` and in
`README.md` must match `SHA256SUMS.asc`.

## 3. Reproducible builds (Guix) — required before dropping "reviewer binary"

The GitHub-built binaries are single-builder and **not** reproducible; the
get-started page therefore labels them "reviewer / playground binaries." To
publish a trustable production release, build with Guix on a capable Linux host
(needs the Guix daemon, KVM, ~tens of GB disk, and hours — not a CI runner):

```
# On a Guix-capable builder, from a clean checkout at the tag:
./contrib/guix/guix-build            # deterministic build, all platforms
./contrib/guix/guix-attest           # produce per-builder attestation (noncodesigned.SHA256SUMS)
# Ideally have a second independent builder run the same and compare:
./contrib/guix/guix-verify           # all builders' SHA256SUMS must match
```

Attach the Guix `SHA256SUMS` + `.asc` to the GitHub Release. Once a Guix build is
published and matches across ≥2 builders, drop the "reviewer binary, not for
production" wording in `tools/get-started.html` and the release notes.

> Status: signing is enforced; the Guix run is the remaining manual step (it
> cannot run in CI or on the WSL2 dev box — use a dedicated builder).

## 4. Signet

Wire-incompatible consensus changes require resetting the public signet from
genesis (see CHANGELOG for the release's compatibility note). The signet runs on
the `ladder-script` host (single seed `85.9.213.194`, `addnode` in
`share/examples/bitcoin-ladder.conf`).
