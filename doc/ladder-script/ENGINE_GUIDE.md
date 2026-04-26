# Ladder Script Engine Guide

## 1. Overview

The Ladder Script Engine is a single-page React application for building,
simulating, and deploying RUNG_TX (version 4) transactions on the Ladder
Script signet. It runs entirely client-side with no build step: open
`tools/ladder-engine/index.html` in any modern browser. The file loads React 18,
ReactDOM 18, and Babel standalone from CDN, then transpiles an inline JSX
`<script type="text/babel">` block at page load.

The engine version string is **GHOST LADDER v2.0**.

### How to run

1. Open `tools/ladder-engine/index.html` directly in a browser (file:// works).
2. For signet features (Send, Spend), either run the ladder-script proxy on
   `http://localhost:8801` or access the hosted version at
   `https://ladder-script.org`.

### Component architecture

The top-level `App` component uses `useReducer` with an `appReducer` and
`INITIAL_STATE`. Two React contexts distribute state and dispatch:

| Context       | Provides                    |
|---------------|-----------------------------|
| `AppContext`  | Full state object           |
| `AppDispatch` | The `dispatch` function     |

Major child components:

- **PalettePanel** (left sidebar, block palette)
- **LadderView** (central ladder diagram, contains RungView / ContactView)
- **PropertiesPanel** / **CoilPropertiesPanel** / **InputPropertiesPanel** (right panel, Properties tab)
- **TxPanel** (right panel, TX tab)
- **SimulationPanel** (right panel, Context tab in Simulate mode)
- **HighlightedJson** (right panel, RPC tab with line-level simulation annotations)
- **RegisterTable** (collapsible bottom table)
- **SignetPanel** (Fund tab full-panel view)
- **SpendPanel** (Spend tab full-panel view)
- **ReviewPanel** (Review tab full-panel view)
- **ConvertPanel** (Convert tab full-panel view)
- **ExamplesModal** (template browser overlay)
- **BlockModal** / **InputModal** / **OutputModal** (inspector overlays)
- **BlockContextMenu** / **InputContextMenu** / **OutputContextMenu** (right-click menus)
- **GuidedWalkthrough** (first-visit tutorial overlay)

---

## 2. Tabs

The header contains six mode tabs. Switching tabs changes what occupies the
central content area.

### Build

Default mode. The three-column layout is visible: block palette on the left,
ladder diagram in the centre, right panel on the right. Drag blocks from the
palette onto rung slots to construct spending conditions. Blocks can be
reordered by dragging within or across rungs.

### Simulate

Same three-column layout, but the palette is read-only and the right panel
switches to the Context tab. The scan bar appears above the ladder with
playback controls (reset, step back, play/pause, step forward) and a speed
slider (100 ms to 2000 ms). Blocks can be force-overridden with Alt+click
(cycles through FORCE ON, BLOCK OFF, AUTO). Clicking a rung label starts
step-through for that rung. The JSON viewer in the RPC tab shows line-level
annotations (cursor, passed, failed, executed, blocked).

### Convert

Full-width panel replacing the three-column layout. Paste JSON from
`decoderung`, `createrungtx`, or `decoderawtransaction` and click
VIEW AS LADDER to import it into the builder. Works offline with no signet
connection.

### Send

Full-width SignetPanel. Connects to the signet node to:
- Check node status, wallet balance, mempool info, and recent blocks.
- Generate a new signet address.
- Request test coins from the faucet.
- Execute the three-step pipeline: CREATE (createrungtx) then SIGN
  (signrawtransactionwithwallet) then BROADCAST (sendrawtransaction).
- Look up transactions by txid.
- Decode raw hex and validate rung transactions.

The panel auto-detects the signature scheme from the diagram (Schnorr, ECDSA,
or any post-quantum scheme) and supports auto or none change modes.

### Spend

Full-width SpendPanel. Lists saved fund records from localStorage. Select a
record, choose which rung (spending path) to use, pick a vout, enter a
destination address, and execute the spend pipeline. The engine builds the
witness, signs with stored keys, and broadcasts.

### Review

Full-width ReviewPanel. Shows a session transaction log stored in
localStorage (up to 50 entries). Each entry can hold both the fund JSON and
the spend JSON side by side, with badges indicating which are present. Click
an entry to view, copy, or compare the raw JSON.

---

## 3. Block Palette

The left sidebar organises **65 block types** into
**11 families**. Each family has a colour-coded dot. Groups are collapsible.
Hovering a palette item shows a tooltip with the block description and hex
type code.

| Family      | Colour    | Blocks |
|-------------|-----------|--------|
| SIGNATURE   | `#ff1744` | SIG, MULTISIG, ADAPTOR_SIG, MUSIG_THR, KEY_REF_SIG |
| TIMELOCK    | `#ff6d00` | CSV, CSV_TIME, CLTV, CLTV_TIME |
| HASH        | `#00e676` | TAGGED, GUARDED |
| COVENANT    | `#2979ff` | CTV, VAULT, AMT_LOCK |
| RECURSION   | `#aa00ff` | REC_SAME, REC_MOD, REC_UNTIL, REC_COUNT, REC_SPLIT, REC_DECAY |
| ANCHOR      | `#ffea00` | ANCHOR, A_CHAN, A_POOL, A_RESV, A_SEAL, A_ORACLE, DATA_RET |
| PLC         | `#ff4081` | HYST_FEE, HYST_VAL, TMR_CONT, TMR_OFF, LATCH_S, LATCH_R, CTR_DN, CTR_PRE, CTR_UP, COMPARE, SEQ, ONE_SHOT, RATE_LIM, COSIGN |
| COMPOUND    | `#ffffff` | TL_SIG, HTLC, HASH_SIG, PTLC, CLTV_SIG, TL_MULTI, ANCHOR_FEE |
| GOVERNANCE  | `#9e9e9e` | EPOCH, WT_LIMIT, IN_COUNT, OUT_COUNT, REL_VAL, ACCUM, OUT_CHK |
| LEGACY      | `#00e5ff` | P2PK, P2PKH, P2SH, P2WPKH, P2WSH, P2TR, P2TR_S |
| QABIO       | `#9b59b6` | QABI_PRIME, QABI_SPEND, PQ_BATCH |

An internal block type `OUTPUT_REF` (not in the palette) references named
output coils from other rungs.

---

## 4. Building Ladders

### Adding rungs

- Click **+ RUNG** in the ladder toolbar to append an empty rung (max 8).
- Click **+ CHANGE** to add a pre-configured SIG change output rung.
- Drop a block from the palette onto the "+ ADD RUNG" zone at the bottom.

### Adding blocks

- Drag a block type from the palette onto any of the 8 slots in a rung.
- Each rung supports up to 8 blocks.
- Blocks within a rung use AND logic: all must be satisfied.
- Rungs use OR logic: any satisfied rung unlocks the output.

### Rung labels

Double-click the rung number to rename it (max 12 characters, auto-uppercased).
Default labels follow the pattern R000, R001, etc.

### Block configuration

Click a block to select it and edit its fields in the Properties panel.
Double-click a block to open the inline name editor. Right-click for the
context menu (Rename, Inspect, Fill Test Data, Invert, Duplicate, Delete).

### Inversion

Any block can be inverted (NOT). An inverted block flips SATISFIED to
UNSATISFIED and vice versa. Visual indicator: a red diagonal line through the
block body and a "NOT" label above it. Toggle via the context menu or the
checkbox in the Properties/Inspector panels.

### Dragging and reordering

- Blocks can be dragged between slots within a rung to reorder.
- Blocks can be dragged across rungs (cross-rung move).
- Rung labels are draggable to reorder rungs. Arrow buttons on hover also
  move rungs up/down.
- The **Justify Left** button (`\u2AEF`) in the toolbar packs all blocks to
  leftmost slots.

### Fill Test Data

The toolbar button "FILL TEST DATA" populates all empty fields across all
blocks with deterministic test values. Individual blocks can be filled via
their context menu or the inspector modal.

---

## 5. Right Panel

The right panel has a draggable resize handle on its left edge (200 px to
600 px). Its tab bar changes depending on mode.

### Properties tab (Build mode)

Shown when a block, input contact, or coil is selected.

- **Block selected:** Shows block type, name input, inverted checkbox, and
  all configurable fields with tooltips. Buttons for TEST DATA and
  EXPAND (opens BlockModal inspector). OUTPUT_REF blocks get a dropdown of
  named coils. SCHEME fields get a dropdown with SCHNORR, ECDSA, FALCON-512,
  FALCON-1024, DILITHIUM3, and SPHINCS+-SHA2 options.
- **Input contact selected:** InputPropertiesPanel showing TX input
  (UTXO) checkboxes and relay reference checkboxes.
- **Coil selected:** CoilPropertiesPanel showing coil name, coil type
  dropdown, wire format settings (coil type, attestation, scheme), and TX
  output assignment dropdown.

### TX tab (Build mode)

TxPanel for configuring transaction inputs, outputs, and locktime.
Each input has TXID, VOUT, and Sequence fields. Each output has Address and
Amount (sats) fields. Summary section shows input count, total output amount,
and estimated vsize.

### Context tab (Simulate mode)

SimulationPanel with context inputs: Block Height, CSV Blocks, CSV Seconds,
Median Time, Input Amount (sats), Output Amount (sats), Fee Rate. Text areas
for available public keys, known preimages, known templates, and known
Merkle roots.

### RPC tab (both modes)

Shows the `createrungtx` wire-format JSON. In Build mode this is plain green
text. In Simulate mode it is rendered by HighlightedJson with line-level
colour coding (green for passed/executed, red for failed/blocked, pulsing
white for the active cursor, dim for neutral/pending).

---

## 6. Simulation

### Scan playback

The scan bar provides VCR-style controls. The engine builds a flat scan
sequence: for each rung, it visits the input contact, then each block
left-to-right, then the coil. The speed slider controls delay between steps
(100 ms fast to 2000 ms slow).

Scan phases: `idle`, `running`, `paused`, `done`.

Position display format: `R00.IN`, `R00.B0`, `R00.B1`, ..., `R00.OUT`.

### Step-through

Click a rung label in Simulate mode to start step-through for that rung.
The first block pulses green ("step-next"). Click it to pass and advance.
After all blocks pass, the coil fires (SPENT) and the rung is marked as
executed after a 600 ms delay.

### Forced blocks

Alt+click a block in Simulate mode to cycle its force state:
1. **FORCE** (forced ON, green) - block always satisfied.
2. **BLOCK** (forced OFF, red) - block always unsatisfied.
3. **AUTO** (no override) - normal evaluation.

A force badge appears on the block.

### Register table

The collapsible bottom panel shows one row per block with columns: Tag
(e.g. R000.B0), Type, Value, and Status (ENERGIZED / OFF / FAULT in Simulate
mode). Status indicators use symbols: filled square for ENERGIZED, light shade
for OFF, dark shade for FAULT.

### Evaluation

Each block type has an `evaluate(block, simState)` method in BlockRegistry
returning `'satisfied'`, `'unsatisfied'`, or `'unknown'`. The wrapper
`evaluateBlock()` checks forced overrides first, then calls the registry
method, then applies inversion. A rung is energized when all its blocks are
satisfied and all its relay references (outputRefs) are satisfied.

---

## 7. Coil Types

Each rung has an output coil. The visual symbol and engine semantics:

| Type       | Symbol | Label       | Meaning |
|------------|--------|-------------|---------|
| standard   | `( )`  | Standard    | Normal spend output |
| latch      | `(L)`  | Latch Set   | Latching output |
| unlatch    | `(U)`  | Unlatch     | Reset a latch |
| retentive  | `(M)`  | Retentive   | State-retaining output |
| negated    | `(/)`  | Negated     | Output inverted |
| relay      | `\u25C7R` | Relay     | Internal logic gate, not tied to a TX output |

### Wire-level coil types

Configured in the output inspector under "Wire Format":

| Wire Type     | Meaning |
|---------------|---------|
| `UNLOCK`      | Standard spend |
| `UNLOCK_TO`   | Spend to address + conditions |

### Attestation types

| Attestation  | Meaning |
|--------------|---------|
| `INLINE`     | Signatures in witness data — the only defined mode |

Earlier draft modes (`AGGREGATE`, `DEFERRED`) were removed from the enum entirely.
For tx-level FALCON-512 aggregation see the QABIO playground.

### Signature schemes

| Scheme        | Description |
|---------------|-------------|
| `SCHNORR`     | BIP-340 default |
| `ECDSA`       | Legacy |
| `FALCON512`   | Post-quantum NIST FIPS 206 |
| `FALCON1024`  | Post-quantum NIST FIPS 206 Level 5 |
| `DILITHIUM3`  | Post-quantum NIST FIPS 204 (ML-DSA-65) |
| `SPHINCS_SHA` | Post-quantum NIST FIPS 205 (SLH-DSA) |

---

## 8. Signet Mode (Send Tab)

The SignetPanel connects to the signet API. The base URL is
`http://localhost:8801` when running locally, or `https://ladder-script.org`
when hosted.

### API endpoints used

| Endpoint                                | Method | Purpose |
|-----------------------------------------|--------|---------|
| `/api/ladder/status`                    | GET    | Node status check |
| `/api/ladder/wallet/balance`            | GET    | Wallet balance |
| `/api/ladder/wallet/address`            | GET    | Generate new address |
| `/api/ladder/wallet/keypair`            | GET    | Generate address + pubkey + privkey |
| `/api/ladder/wallet/utxos`              | GET    | List UTXOs |
| `/api/ladder/faucet`                    | POST   | Request test coins |
| `/api/ladder/createrungtx`              | POST   | Create unsigned v4 RUNG_TX |
| `/api/ladder/sign`                      | POST   | Sign transaction (raw signrungtx path) |
| `/api/ladder/signladder`                | POST   | Sign via descriptor notation (one-call) |
| `/api/ladder/broadcast`                 | POST   | Broadcast signed transaction |
| `/api/ladder/tx/{txid}`                 | GET    | Look up transaction |
| `/api/ladder/decode`                    | POST   | Decode ladder witness hex |
| `/api/ladder/decode-tx`                 | POST   | Decode raw transaction hex |
| `/api/ladder/validate`                  | POST   | Validate ladder witness |
| `/api/ladder/ctv-hash`                  | POST   | Compute BIP-119 CTV hash |
| `/api/ladder/pq/keypair`               | POST   | Generate PQ keypair |
| `/api/ladder/preimage`                  | GET    | Generate random preimage + hashes |
| `/api/ladder/mempool`                   | GET    | Mempool info |
| `/api/ladder/blocks/recent`             | GET    | Recent blocks |
| `/api/ladder/mine`                      | POST   | Mine a block (regtest) |

### Wallet features

- **Generate New Address**: creates a keypair and displays the address.
- **Faucet**: paste an address and request 0.001 tBTC.
- **UTXO list**: view available unspent outputs.
- **Transaction history**: track funded transactions with confirmation
  polling.

### Create / Sign / Broadcast pipeline

1. **CREATE**: calls `/api/ladder/createrungtx` with inputs, output amounts, and
   a flat `rungs` array (each rung carries `output_index` declaring which output
   it governs). The engine runs `planFund()` to inventory keys, hashes, and
   timelocks, then auto-assigns pubkeys and generates keypairs as needed. A
   fund record is saved to localStorage for later spending.
2. **SIGN**: calls `/api/ladder/sign` with the raw hex and signer data.
3. **BROADCAST**: calls `/api/ladder/broadcast` with the signed hex. A session
   log entry is saved for the Review tab.

---

## 9. Spend Tab

The SpendPanel loads saved fund records from localStorage. It provides:

- **Record list**: all previously funded outputs with txid, amount, scheme,
  and block type checksums.
- **UTXO lookup**: enter a txid and vout to look up a specific output.
- **Rung selection**: choose which spending path (rung index) to use.
- **VOUT selection**: pick which output vout to spend.
- **Destination address**: where to send the funds.
- **Spend execution**: the engine calls each block's `buildSigner()` method
  from BlockRegistry, assembles the witness, signs the spend transaction, and
  broadcasts it. For legacy blocks (P2SH, P2WSH, P2TR_SCRIPT), inner block
  keys are resolved via `_findInnerKey()`.

Spend JSON is attached to the fund entry in the session log via
`updateSessionTxSpend()`.

---

## 10. Review Tab

The ReviewPanel shows session transactions from localStorage (up to 50
entries, stored under key `ghost_session_txlog`). The left sidebar lists
entries with timestamps, txid prefixes, and badges for FUND and SPEND
presence. Selecting an entry shows:

- Fund JSON (formatted, copyable).
- Spend JSON (formatted, copyable) if a spend has been performed.
- Transaction size data when available.

Buttons: REFRESH, CLEAR (wipes the session log).

---

## 11. Convert Tab

The ConvertPanel accepts pasted JSON in three formats:

1. **`decoderung` output**: `{ rungs: [{ blocks: [...], coil: {...} }] }` or
   `{ n_rungs, rungs: [...] }`.
2. **`createrungtx` shared-tree format**: `{ inputs: [...], outputs: [<amount>, ...], rungs: [{ output_index, blocks: [...] }, ...] }`.
3. **`decoderawtransaction` output**: raw tx with `version: 4` and
   `vout[].rung_conditions`.

The converter function `decodedToBuilderRungs()` normalizes all three formats
into the builder's internal rung model and dispatches a `VIEW_AS_LADDER`
action to populate the diagram. Works entirely offline.

---

## 12. Keyboard Shortcuts

| Key                        | Action |
|----------------------------|--------|
| `Escape`                   | Close context menu, modal, step-through, examples, or exit fullscreen (in priority order) |
| `F11`                      | Toggle fullscreen mode |
| `Delete` / `Backspace`     | Delete selected block, clear selected input assignments, or clear selected coil assignments (Build mode only, ignored when focus is in a text input) |
| `Ctrl+Scroll` / `Meta+Scroll` | Fine zoom (5% increments) |
| `Scroll`                   | Zoom (10% increments) |
| `Shift+Scroll`             | Horizontal pan |
| `Middle-click drag`        | Pan the ladder view |
| `Shift+left-click drag`    | Pan the ladder view |
| `Alt+click` (Simulate)     | Cycle block force state (ON / OFF / AUTO) |
| `Enter`                    | Close modal (when not in a text input) |

---

## 13. Status Bar

The bottom 24 px bar displays, left to right:

1. **Rung count** with green/amber dot (green if at least one block exists).
2. **Block count** with limits reminder: "N BLOCKS (8/RUNG MAX, 8 RUNGS MAX)".
3. **Energized count** (Simulate mode only) with amber/red dot.
4. **Unassigned rungs** warning (red) if any rungs lack a TX output assignment.
5. **OUTPUT_REF deprecation** warning (amber) if any OUTPUT_REF blocks exist.
6. **Validation status**: red dot + error count, amber dot + warning count,
   or green dot + "VALID". Clicking opens the validation panel.
7. **Spacer**.
8. **Tooltip toggle** button ("? ON" / "? OFF").
9. **Version label**: "GHOST LADDER v2.0".

---

## 14. Tutorial (Guided Walkthrough)

The GuidedWalkthrough component auto-shows on first visit (controlled by
`localStorage` key `ladder-walkthrough-complete`). It is an 8-step overlay
with spotlight masking, step counter, progress dots, and SKIP / BACK / NEXT
buttons.

| Step | Title | Focus |
|------|-------|-------|
| 1 | Welcome to Ladder Script Engine | None (centered) |
| 2 | Templates | EXAMPLES button |
| 3 | The Ladder Diagram | Ladder area |
| 4 | Signet Mode | Mode tabs |
| 5 | Generate Keys | Mode tabs |
| 6 | Get Test Coins | Mode tabs |
| 7 | Create & Broadcast | Mode tabs |
| 8 | You're Ready! | None (centered) |

Press Escape or click SKIP at any time to dismiss. Completion is persisted
so the walkthrough does not reappear.

---

## 15. Templates

The ExamplesModal displays a two-column grid of **56 template programs**.
Each card shows a title, description, and coloured tag badges. Clicking a
card loads its rungs, TX inputs, and TX outputs into the builder. The
canonical list lives in `tools/test-presets.py` (each `PRESETS.append(...)`
mirrors a card; the source script also drives the end-to-end signet test
that exercises every preset). The first 48 templates are listed below;
the remaining 8 are recent additions covering DATA_RETURN payloads,
RECURSE_SAME identity carry, OUTPUT_CHECK governance, and several PQ_BATCH
batch shapes.

Selected template names:

1. 2-of-3 MULTISIG VAULT
2. ATOMIC SWAP (HTLC)
3. ADAPTOR SIG SWAP
4. DCA COVENANT CHAIN
5. VAULT WITH UNVAULT + CLAWBACK
6. RATE-LIMITED WALLET
7. DEAD MAN'S SWITCH (INHERITANCE)
8. ESCROW WITH ORACLE
9. PAYMENT CHANNEL
10. SEQUENCED PAYOUT
11. FEE-GATED COVENANT
12. ONE-SHOT TRIGGER + LATCH
13. RECURSIVE SPLIT (TREE)
14. BLOCK-HEIGHT TIMELOCK + COMPARE
15. COUNTER-UP SUBSCRIPTION
16. QUANTUM-SAFE VAULT
17. QUANTUM VAULT + CHILDREN
18. MULTI-INPUT CONSOLIDATION
19. MUSIG_THRESHOLD TREASURY
20. PTLC PAYMENT CHANNEL
21. CLTV_SIG VESTING SCHEDULE
22. TIMELOCKED_MULTISIG VAULT RECOVERY
23. HTLC COMPACT SWAP
24. HASH_SIG ATOMIC CLAIM
25. GOVERNANCE-GATED TREASURY
26. ACCUMULATOR ALLOWLIST
27. CLTV_TIME CALENDAR LOCK
28. TIMER WATCHDOG
29. PRESET COUNTER BOARD VOTE
30. ANCHORED CHANNEL + RECURSE_UNTIL
31. SINGLE SIG
32. DUAL SIG
33. SINGLE SIG (DILITHIUM3)
34. SINGLE SIG (FALCON512)
35. SINGLE SIG (FALCON1024)
36. LEGACY P2PKH + RECOVERY
37. LEGACY P2SH MULTISIG VAULT
38. P2TR TAPROOT MIGRATION
39. SINGLE SIG (SPHINCS+)
40. RECURSE_COUNT COUNTDOWN
41. RECURSE_DECAY DIMINISHING RETURNS
42. KEY_REF_SIG RELAY KEY
43. LEGACY P2WSH MULTISIG
44. ANCHOR TAG
45. ANCHOR POOL (VTXO)
46. ANCHOR RESERVE
47. ANCHOR SEAL
48. ANCHOR ORACLE

---

## 16. Companion Playgrounds

The Engine handles the full block library, but two specific protocols have
their own dedicated tools — both shipped under `tools/` and reachable from
the [Tools landing page](https://ladder-script.org/tools.html):

- **PQ Batch Playground** (`tools/pq-batch-playground/`) — a focused tool
  for the PQ_BATCH primitive: generate a FALCON-512 keypair, fund N UTXOs
  gated by the same `SHA256(falcon_pubkey)` commit, and watch the spend
  amortise via the tx-local cache (anchor input does the verify, others
  short-circuit). See [`PQ_BATCH_PLAYGROUND_GUIDE.md`](PQ_BATCH_PLAYGROUND_GUIDE.md).
- **QABIO Playground** (`tools/qabio-playground/`) — multi-party batch
  ceremony walkthrough: pick a scenario (3-of-3 happy path, 5-with-1-fail
  escape, 10/20-user realistic, coordinator bails, replace-by-depth),
  step the participants through priming, coordinator signing, batch
  broadcast. See [`QABIO_PLAYGROUND_GUIDE.md`](QABIO_PLAYGROUND_GUIDE.md).

The Engine can build PQ_BATCH and QABIO outputs directly from its block
palette (the QABIO family entries: `QABI_PRIME`, `QABI_SPEND`, `PQ_BATCH`).
The playgrounds exist because the multi-input cache amortisation
(PQ_BATCH) and the multi-party priming-then-signing flow (QABIO) are
easier to demonstrate end-to-end with dedicated UIs than to drive from
the general-purpose Engine.
