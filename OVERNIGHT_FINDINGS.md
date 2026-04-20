# Overnight findings — 2026-04-19 ~22:00 UTC

Session goal: push latest binary to the ladder-script signet VPS so the
engine/playground could exercise the latest consensus code, then run
solo static + smoke tests on the engine and playground while the user
sleeps. What I hit and what I left behind.

## 1. ROOT CAUSE IDENTIFIED (morning of 2026-04-20)

The "regression" is not a regression — it's the deliberate tagged-hash
versioning from commit **`e82178da6a`** (2026-04-18,
"tagged-hash: version the five Ladder* domain separators to /v1").
That commit renamed the five Ladder tagged-hash domain separators:

    LadderLeaf            → LadderLeaf/v1            (Merkle tree leaves)
    LadderInternal        → LadderInternal/v1        (Merkle tree internal nodes)
    LadderSighash         → LadderSighash/v1
    LadderKeyPathSighash  → LadderKeyPathSighash/v1
    LadderTweak           → LadderTweak/v1

Every hash in the MLSC Merkle path depends on those tags. The signet
chain was mined on **2026-04-17**, one day before the rename. The new
binary uses `/v1` tags, computes a different Merkle root from the same
witness, and reports "MLSC Merkle path verification failed" on the
first TX_MLSC spend (block 113, tx `b153ecfe...`).

The versioning itself is intentional and correct: without a version
suffix, a future Bitcoin BIP taking "Ladder*" as a tag would silently
collide with ours. The commit message justifies this.

**Fix:** regenerate the signet chain under the new tags. The existing
1161 blocks are orphaned by design. No code change is needed.

**Signet regen procedure (for later, when ready):**

1. `ssh ladder-script "sudo systemctl stop bitcoind"`
2. `ssh ladder-script "sudo rm -rf /home/ghost/.bitcoin/signet/{blocks,chainstate,banlist.json,fee_estimates.dat,mempool.dat,peers.dat}"`
   (keep `bitcoin.conf`, `signet.{conf,json}` if any, `wallets/`)
3. `ssh ladder-script "sudo rm /etc/systemd/system/bitcoind.service.d/reindex.conf && sudo systemctl daemon-reload"`
4. Deploy the HEAD binary (see §3 backup steps — same procedure as
   overnight, just this time it'll succeed because the chain is
   empty).
5. `sudo systemctl start bitcoind`
6. Mine fresh signet blocks (need the custom signet challenge signer —
   check `bitcoin.conf` for `signetchallenge=` and recover the signer
   key from wherever it was stored; if lost, generate a new one and
   update conf).

## 1b. Original session notes (for history)

**Symptom.** The freshly-built `bitcoind` from HEAD (`989004e433`)
rejects block **113** of the existing signet chain during
`-reindex-chainstate`:

    Block: 00000362ed0a715641b3f22d2f32bd32ae4f04da135c74583e9db334211bebf9
    Height: 113
    Date: 2026-04-17T13:42:12Z
    Input: 0 of tx b153ecfe8663364442f8798a01a61bb0ac5aa718db27f90e4b0138f19eca4bb2
      (wtxid 4a65ad84a511bf0b0d3e1562293cccd0d313281a1adf19ff081865f339fa136a)
    Spending: bee85ee76b946393fa89010f57c99f8adb8336327a44eba97c245233149658ad:0
    Error: "MLSC Merkle path verification failed: computed root does not match expected root"
    → block-script-verify-flag-failed (unknown error)

**Likely cause.** Something in Stage 1.3 (the uint32 truncation guards:
`4264587067` COMPARE op byte, `f02387b64f` QABI_PRIME uint32,
`99bd7882de` RECURSE_COUNT negative, `a4782caa8e` RELATIVE_VALUE
uint32, `c366dcc846` VAULT_LOCK, `1a23fa32c8` CSV/CLTV) or Stage 2
(the CTV hash `WriteLE32`/`WriteLE64` refactor in
`src/rung/blocks/covenant.cpp`) tightened a rule or changed a hash
computation that a historically-mined block on this signet chain
violates.

The **old binary also fails past block 112** after the forced reindex,
for the same reason — the rule/behaviour change landed in Stage 1.3,
not HEAD, so it's been present in every build since that commit. The
2-day-stale signet was running in `-reindex-chainstate -daemon` mode
the whole time, which masked the issue: the chainstate had already
been reindexed once, successfully, under the old (pre-Stage-1.3)
rules. When we stopped the daemon cleanly the chainstate went into
a state that requires another reindex, which now hits the changed
rule and stops.

**What to do tomorrow.**

1. Extract the raw tx bytes for `b153ecfe...` from the block files
   on the VM:
   ```
   ssh ladder-script "sudo -u ghost bitcoin-cli -datadir=/home/ghost/.bitcoin \
     -conf=/home/ghost/.bitcoin/bitcoin.conf getrawtransaction \
     b153ecfe8663364442f8798a01a61bb0ac5aa718db27f90e4b0138f19eca4bb2 2"
   ```
   (Use the old binary first; tip is at 112 so the tx won't be in
   the chainstate, but it might still be retrievable via txindex which
   is enabled at height 1161. If not, `sudo xxd blk00000.dat` + manual
   scan.)

2. `git bisect` between a pre-Stage-1.3 commit and HEAD, running a
   unit test that replays this exact tx against an `-accept=always`
   block to find the commit that flipped its validity.

3. Decide: is the new rule wrong (drop/loosen) or was the block
   actually invalid and only now is it being noticed?

4. Add a functional test `feature_rung_stage13_replay.py` that
   exercises whatever pattern this is so this doesn't regress silently
   again. (Existing `feature_rung_tx.py` + `feature_qabi.py` clearly
   don't cover this case.)

Two clues that may help:
- It's a spend, not a QABI / PLC / governance tx.
- It hits `MLSC Merkle path verification failed` — so it's in
  `src/rung/evaluator.cpp` MLSC path, not inside any Eval*Block.
  Could be the LE-write refactor in `blocks/covenant.cpp` actually
  changed the `ComputeCTVHash` output... but CTV is an expected
  consensus change, not MLSC. More likely the `CheckLadderTweakRaw`
  port in `7527e4dd14` — if that hash differs byte-for-byte from
  the old `XOnlyPubKey::CheckLadderTweak`, tweak verification would
  fail. Worth checking first.

## 2. Signet node state

- SSH: `ladder-script` (root = `/var/www/ladder-script`, also hosts
  `bitcoind`).
- Binary on VM: **old binary restored** from
  `/usr/local/bin/bitcoind.bak.20260419-214540`. The new binary from
  this session is no longer on the VM (cleaned up from `/tmp`).
- systemd override at `/etc/systemd/system/bitcoind.service.d/reindex.conf`
  adds `-reindex-chainstate` to the `ExecStart`. Node is running with
  tip at block **112** (was 1161 before the session). RPC responds,
  so engine/playground queries will get a signet response — just
  with a stale tip.
- The 1049 blocks between 112 and 1161 are still on disk in
  `signet/blocks/blk*.dat`. Recovery path: fix the consensus
  regression → re-run `-reindex-chainstate` → chainstate catches
  back up.
- Remove the override once the node is healthy:
  `sudo rm /etc/systemd/system/bitcoind.service.d/reindex.conf && sudo systemctl daemon-reload`

## 3. Engine (`tools/ladder-engine/index.html`) audit

**Smoke test** (`test/tools/engine_smoke.js`): all structural checks
pass under the new counts.

    Engine file: 607 KB
    === Templates ===        PASS: 52 templates (>=39 baseline)
    === Block Types ===       PASS: 120 entries across BLOCK_FAMILIES + getTypeHex
    === getTypeHex ===        PASS: >=61 entries, OUTPUT_CHECK at 0x0807
    === Dead Code ===         PASS: no COVENANT coil, AGGREGATE attestation, or watch mode

(Side fix along the way: `ENGINE_PATH` in the smoke test had one too
few `..` — pointed at `test/tools/tools/ladder-engine/index.html`
instead of `tools/ladder-engine/index.html`. Corrected; smoke test
now runs cleanly. Change included in today's commits.)

**Coverage gap vs. consensus library.**

Blocks registered by `src/rung/blocks/*.cpp` but missing from the
engine's `type:` definitions:

    ANCHOR_FEE
    P2PK_LEGACY
    P2PKH_LEGACY
    P2SH_LEGACY
    P2TR_LEGACY
    P2TR_SCRIPT_LEGACY
    P2WPKH_LEGACY
    P2WSH_LEGACY

The engine can't build or visualise a ladder that uses any of the
legacy P2* wrappers or the ANCHOR_FEE block. Not a crash, but a
functional gap if a user wants to build a legacy-compatible ladder
from the UI.

**State-management migration status.** 65 `useState` hooks still in
the App component, despite the reducer + contexts + dispatch being
wired (per the 38-day-old `engine-v2-state-management-plan.md`, Phase
C12 is the remaining "migrate hooks to reducer" work). Current
dispatched actions include SELECT_BLOCK, SELECT_COIL, SELECT_INPUT,
DELETE_BLOCK, UPDATE_RUNGS (generic fn-based), SET_MODE. The rest
are still per-hook.

No stale references to `LadderSignatureChecker`, `BatchVerifier`, or
`tx_core` in the engine source — good.

## 4. Playground (`tools/qabio-playground/index.html`) audit

- 2,112 lines, 5 `useState` hooks (no reducer — simpler app).
- QABI_PRIME referenced 9× and QABI_SPEND referenced 14× — looks
  complete.
- All 4 key pages return HTTP 200 via the live nginx:
  `ladder-script.org/`, `ladder-script.org/ladder-engine/`,
  `ladder-script.org/qabio-playground/`, `ladder-script.org/docs/`.
- **Not validated against live signet.** The node is at tip 112
  (wasn't at the time the playground was last exercised) so any
  flow that depends on recent blocks will see stale state. Real
  end-to-end test against signet is gated on the consensus
  regression fix in §1.

## 5. Not done tonight (for tomorrow)

- No `git bisect` for the regression — that needs the actual failing
  tx bytes, which the user can pull tomorrow with the old binary.
- No commits pushed overnight. Last pushed commit: `989004e433`.
- No doc changes (docs pass deferred to tomorrow per user).
- No interactive engine/playground UX walk-through — that's explicitly
  hands-on work.
- The engine's 65 remaining `useState` hooks weren't migrated. That
  work is in scope for Stage 5 of the roadmap, not this session.

## Starting point for the morning

1. Read this file.
2. Dump the block-113 tx (`b153ecfe...`) bytes.
3. Bisect back to find which Stage 1.3 commit flipped its validity.
4. Pick: is the new rule wrong, or was the block actually invalid?
5. Fix and ship a fresh binary to the signet VPS (re-run the same
   process; backup steps are in §3 of this file).
6. `ssh ladder-script "sudo rm /etc/systemd/system/bitcoind.service.d/reindex.conf && sudo systemctl daemon-reload && sudo systemctl restart bitcoind"`
   once the node is healthy.
