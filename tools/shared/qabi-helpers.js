// QABIO helper wrappers — thin layer over the ladder proxy endpoints.
// Depends on window.LadderAPI (ladder-api.js must load first).
// Exposes window.QABI.

(function(){
  if (!window.LadderAPI) {
    throw new Error('qabi-helpers.js requires ladder-api.js to load first.');
  }
  const { apiCallBase } = window.LadderAPI;

  const FALCON512_PUBKEY_SIZE = 897;
  const FALCON512_SIG_SIZE = 666;
  const QABI_BLOCK_MAX_SOFT = 65536;
  const QABI_BLOCK_MAX_HARD = 262144;
  const BYTES_PER_INPUT = 432;
  const VBYTES_PER_INPUT = 162;
  const STANDARD_RELAY_MAX_N = 618;

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
  function estimateBatchVsize(n, outputs) {
    const perInput = VBYTES_PER_INPUT;
    const fixedOverhead = 180;
    const perOutput = 31;
    const outs = Math.max(1, outputs || n);
    return fixedOverhead + perInput * n + perOutput * outs;
  }

  // A solo QABIO spend (1 participant, own tx) costs significantly more than
  // a regular tx because it carries its own FALCON-512 sig (666B witness ≈
  // 167 vB) + a per-participant QABI block (~150B ≈ 38 vB) + MLSC witness
  // + primed input. Approximate: 450 vB per individual QABIO spend.
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
    FALCON512_SIG_SIZE,
    QABI_BLOCK_MAX_SOFT,
    QABI_BLOCK_MAX_HARD,
    BYTES_PER_INPUT,
    VBYTES_PER_INPUT,
    STANDARD_RELAY_MAX_N,
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
