// QABIO helper wrappers — thin layer over the ladder proxy endpoints.
// Depends on window.LadderAPI (ladder-api.js must load first).
// Exposes window.QABI.

(function(){
  if (!window.LadderAPI) {
    throw new Error('qabi-helpers.js requires ladder-api.js to load first.');
  }
  const { apiCallBase } = window.LadderAPI;

  const FALCON512_PUBKEY_SIZE = 897;
  const FALCON512_SIG_SIZE_MAX = 666;  // FALCON sigs are variable-length up to this; signqabo returns the actual sig_size.
  const FALCON512_SIG_SIZE = FALCON512_SIG_SIZE_MAX;  // Backwards-compat alias
  const QABI_BLOCK_MAX_SOFT = 65536;
  const QABI_BLOCK_MAX_HARD = 262144;
  // Per-cosigner cost on the wire (~409 B) and after segwit witness discount
  // (~139 vB asymptote at N=500+; ~143 vB at N=100). Numbers from
  // doc/ladder-script/QABIO.md §8.
  const BYTES_PER_INPUT = 409;
  const VBYTES_PER_INPUT = 139;
  // Standard-relay cap binds at ~720 participants (100,000 vB / ~139 vB).
  // Per QABIO.md §8.
  const STANDARD_RELAY_MAX_N = 720;

  // Proxy endpoint expects auth_seed + chain_length (not seed/length).
  async function authchain(authSeed, chainLength, depth) {
    const body = { auth_seed: authSeed, chain_length: chainLength };
    if (depth !== undefined) body.depth = depth;
    return apiCallBase('/api/ladder/qabi/authchain', body);
  }

  async function buildBlock({ coordinatorPubkey, primeExpiryHeight, batchId, entries, outputsConditionsRoot, outputValues }) {
    return apiCallBase('/api/ladder/qabi/buildblock', {
      coordinator_pubkey: coordinatorPubkey,
      prime_expiry_height: primeExpiryHeight,
      batch_id: batchId || '00'.repeat(32),
      entries,
      outputs_conditions_root: outputsConditionsRoot,
      output_values: outputValues,
    });
  }

  async function blockInfo(qabiBlockHex) {
    return apiCallBase('/api/ladder/qabi/blockinfo', { qabi_block: qabiBlockHex });
  }

  async function sighash(hexTx) {
    return apiCallBase('/api/ladder/qabi/sighash', { hex: hexTx });
  }

  async function signQabo(hexTx, privkey) {
    return apiCallBase('/api/ladder/qabi/signqabo', { hex: hexTx, privkey });
  }

  async function generateKeypair(scheme) {
    // FALCON/Dilithium/SPHINCS+ keygen lives under /pq/, not /qabi/.
    return apiCallBase('/api/ladder/pq/keypair', { scheme: scheme || 'FALCON512' });
  }

  // Closed-form amortised batch size estimate, from QABIO.md §8.
  // Used for live metrics before the batch tx is actually built.
  // Fit: total vsize ≈ fixedOverhead + perInput·N + perOutput·outs, where
  // fixedOverhead ≈ 400 vB (FALCON sig + qabi_block scaffolding + tx
  // preamble after witness discount), perInput ≈ 139 vB (asymptote), and
  // perOutput ≈ 8 vB (v4 outputs are 8 bytes on the wire — just nValue).
  function estimateBatchVsize(n, outputs) {
    const perInput = VBYTES_PER_INPUT;
    const fixedOverhead = 400;
    const perOutput = 8;
    const outs = Math.max(1, outputs || n);
    return fixedOverhead + perInput * n + perOutput * outs;
  }

  // A solo QABIO spend (1 participant, own tx) carries the full per-tx
  // FALCON-512 overhead (~666 B sig ≈ 167 vB witness-discounted, plus
  // ~897 B coordinator pubkey ≈ 225 vB, plus the qabi_block scaffolding
  // and one primed-input MLSC witness). The ~409 B/participant baseline
  // already includes amortised QABI overhead; for an N=1 spend the
  // overhead isn't amortised so the per-tx cost is much higher.
  // Estimated 450 vB per solo QABIO spend (matches the per-cosigner table
  // in QABIO.md §8 at very small N).
  const SOLO_QABIO_SPEND_VBYTES = 450;

  function estimatePerInputCostSavings(n) {
    const batch = estimateBatchVsize(n, n);
    const individual = SOLO_QABIO_SPEND_VBYTES * n;
    return {
      batch,
      individual,
      savedVbytes: individual - batch,
      savedPct: individual > 0 ? ((individual - batch) / individual) * 100 : 0,
      perInputBatch: Math.ceil(batch / n),
      perInputSolo: SOLO_QABIO_SPEND_VBYTES,
    };
  }

  window.QABI = {
    FALCON512_PUBKEY_SIZE,
    FALCON512_SIG_SIZE,         // alias for SIG_SIZE_MAX (backwards-compat)
    FALCON512_SIG_SIZE_MAX,
    QABI_BLOCK_MAX_SOFT,
    QABI_BLOCK_MAX_HARD,
    BYTES_PER_INPUT,
    VBYTES_PER_INPUT,
    STANDARD_RELAY_MAX_N,
    SOLO_QABIO_SPEND_VBYTES,
    authchain,
    buildBlock,
    blockInfo,
    sighash,
    signQabo,
    generateKeypair,
    estimateBatchVsize,
    estimatePerInputCostSavings,
  };
})();
