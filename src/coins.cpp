// Copyright (c) 2012-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <coins.h>

#include <consensus/consensus.h>
#include <logging.h>
#include <random.h>
#include <rung/conditions.h>  // MLSC_SYNTHETIC_MARKER
#include <util/trace.h>

TRACEPOINT_SEMAPHORE(utxocache, add);
TRACEPOINT_SEMAPHORE(utxocache, spent);
TRACEPOINT_SEMAPHORE(utxocache, uncache);

std::optional<Coin> CCoinsView::GetCoin(const COutPoint& outpoint) const { return std::nullopt; }
uint256 CCoinsView::GetBestBlock() const { return uint256(); }
std::vector<uint256> CCoinsView::GetHeadBlocks() const { return std::vector<uint256>(); }
bool CCoinsView::BatchWrite(CoinsViewCacheCursor& cursor, const uint256 &hashBlock) { return false; }
std::unique_ptr<CCoinsViewCursor> CCoinsView::Cursor() const { return nullptr; }

bool CCoinsView::HaveCoin(const COutPoint &outpoint) const
{
    return GetCoin(outpoint).has_value();
}

CCoinsViewBacked::CCoinsViewBacked(CCoinsView *viewIn) : base(viewIn) { }
std::optional<Coin> CCoinsViewBacked::GetCoin(const COutPoint& outpoint) const { return base->GetCoin(outpoint); }
bool CCoinsViewBacked::HaveCoin(const COutPoint &outpoint) const { return base->HaveCoin(outpoint); }
uint256 CCoinsViewBacked::GetBestBlock() const { return base->GetBestBlock(); }
std::vector<uint256> CCoinsViewBacked::GetHeadBlocks() const { return base->GetHeadBlocks(); }
void CCoinsViewBacked::SetBackend(CCoinsView &viewIn) { base = &viewIn; }
bool CCoinsViewBacked::BatchWrite(CoinsViewCacheCursor& cursor, const uint256 &hashBlock) { return base->BatchWrite(cursor, hashBlock); }
std::unique_ptr<CCoinsViewCursor> CCoinsViewBacked::Cursor() const { return base->Cursor(); }
size_t CCoinsViewBacked::EstimateSize() const { return base->EstimateSize(); }

CCoinsViewCache::CCoinsViewCache(CCoinsView* baseIn, bool deterministic) :
    CCoinsViewBacked(baseIn), m_deterministic(deterministic),
    cacheCoins(0, SaltedOutpointHasher(/*deterministic=*/deterministic), CCoinsMap::key_equal{}, &m_cache_coins_memory_resource)
{
    m_sentinel.second.SelfRef(m_sentinel);
}

size_t CCoinsViewCache::DynamicMemoryUsage() const {
    return memusage::DynamicUsage(cacheCoins) + cachedCoinsUsage;
}

CCoinsMap::iterator CCoinsViewCache::FetchCoin(const COutPoint &outpoint) const {
    const auto [ret, inserted] = cacheCoins.try_emplace(outpoint);
    if (inserted) {
        if (auto coin{base->GetCoin(outpoint)}) {
            ret->second.coin = std::move(*coin);
            cachedCoinsUsage += ret->second.coin.DynamicMemoryUsage();
            if (ret->second.coin.IsSpent()) { // TODO GetCoin cannot return spent coins
                // The parent only has an empty entry for this outpoint; we can consider our version as fresh.
                CCoinsCacheEntry::SetFresh(*ret, m_sentinel);
            }
        } else {
            cacheCoins.erase(ret);
            return cacheCoins.end();
        }
    }
    return ret;
}

std::optional<Coin> CCoinsViewCache::GetCoin(const COutPoint& outpoint) const
{
    if (auto it{FetchCoin(outpoint)}; it != cacheCoins.end() && !it->second.coin.IsSpent()) return it->second.coin;
    return std::nullopt;
}

void CCoinsViewCache::AddCoin(const COutPoint &outpoint, Coin&& coin, bool possible_overwrite) {
    assert(!coin.IsSpent());
    if (coin.out.scriptPubKey.IsUnspendable()) return;
    CCoinsMap::iterator it;
    bool inserted;
    std::tie(it, inserted) = cacheCoins.emplace(std::piecewise_construct, std::forward_as_tuple(outpoint), std::tuple<>());
    bool fresh = false;
    if (!inserted) {
        cachedCoinsUsage -= it->second.coin.DynamicMemoryUsage();
    }
    if (!possible_overwrite) {
        if (!it->second.coin.IsSpent()) {
            throw std::logic_error("Attempted to overwrite an unspent coin (when possible_overwrite is false)");
        }
        // If the coin exists in this cache as a spent coin and is DIRTY, then
        // its spentness hasn't been flushed to the parent cache. We're
        // re-adding the coin to this cache now but we can't mark it as FRESH.
        // If we mark it FRESH and then spend it before the cache is flushed
        // we would remove it from this cache and would never flush spentness
        // to the parent cache.
        //
        // Re-adding a spent coin can happen in the case of a re-org (the coin
        // is 'spent' when the block adding it is disconnected and then
        // re-added when it is also added in a newly connected block).
        //
        // If the coin doesn't exist in the current cache, or is spent but not
        // DIRTY, then it can be marked FRESH.
        fresh = !it->second.IsDirty();
    }
    it->second.coin = std::move(coin);
    CCoinsCacheEntry::SetDirty(*it, m_sentinel);
    if (fresh) CCoinsCacheEntry::SetFresh(*it, m_sentinel);
    cachedCoinsUsage += it->second.coin.DynamicMemoryUsage();
    TRACEPOINT(utxocache, add,
           outpoint.hash.data(),
           (uint32_t)outpoint.n,
           (uint32_t)it->second.coin.nHeight,
           (int64_t)it->second.coin.out.nValue,
           (bool)it->second.coin.IsCoinBase());
}

void CCoinsViewCache::EmplaceCoinInternalDANGER(COutPoint&& outpoint, Coin&& coin) {
    cachedCoinsUsage += coin.DynamicMemoryUsage();
    auto [it, inserted] = cacheCoins.try_emplace(std::move(outpoint), std::move(coin));
    if (inserted) CCoinsCacheEntry::SetDirty(*it, m_sentinel);
}

void AddCoins(CCoinsViewCache& cache, const CTransaction &tx, int nHeight, bool check_for_overwrite) {
    bool fCoinbase = tx.IsCoinBase();
    const Txid& txid = tx.GetHash();
    for (size_t i = 0; i < tx.vout.size(); ++i) {
        bool overwrite = check_for_overwrite ? cache.HaveCoin(COutPoint(txid, i)) : fCoinbase;
        // Coinbase transactions can always be overwritten, in order to correctly
        // deal with the pre-BIP30 occurrences of duplicate coinbase transactions.
        cache.AddCoin(COutPoint(txid, i), Coin(tx.vout[i], nHeight, fCoinbase), overwrite);
    }

    // TX_MLSC: write a synthetic root entry at (txid, MLSC_ROOT_VOUT).
    // This stores the conditions_root once, enabling UTXO deduplication.
    // Individual MLSC coins store a 1-byte scriptPubKey (MLSC_MARKER) via
    // compression; the root is recovered from this synthetic entry at spend
    // time. The synthetic-root marker is distinct from MLSC_MARKER so the
    // compressor does not strip the root.
    //
    // v0.13+: payload is 35 bytes —
    //   0xDE || conditions_root[32] || refcount_LE_u16
    // The refcount counts unspent non-DATA_RETURN MLSC outputs from this
    // creating tx. Decremented in UpdateCoins on each MLSC input spend;
    // deleted when refcount reaches zero. DATA_RETURN outputs (nValue == 0)
    // are unspendable and not counted; if every output is DATA_RETURN
    // (refcount == 0), no synthetic entry is written.
    if (tx.version == CTransaction::RUNG_TX_VERSION) {
        uint16_t refcount = 0;
        for (const auto& out : tx.vout) {
            if (out.nValue > 0) refcount++;
        }
        if (refcount == 0) return; // pure-DATA_RETURN tx; no spendable MLSC coins
        CTxOut root_out;
        root_out.nValue = 0; // sentinel: not a real output, not spendable
        root_out.scriptPubKey.resize(MLSC_SYNTHETIC_PAYLOAD_SIZE);
        root_out.scriptPubKey[0] = rung::MLSC_SYNTHETIC_MARKER;
        memcpy(&root_out.scriptPubKey[1], tx.conditions_root.data(), 32);
        root_out.scriptPubKey[33] = static_cast<uint8_t>(refcount & 0xFF);
        root_out.scriptPubKey[34] = static_cast<uint8_t>((refcount >> 8) & 0xFF);
        cache.AddCoin(COutPoint(txid, MLSC_ROOT_VOUT), Coin(std::move(root_out), nHeight, false), false);
    }
}

void DecrementMLSCSyntheticRefcount(CCoinsViewCache& cache,
                                     const Txid& creating_txid,
                                     uint256* deleted_root_out)
{
    const COutPoint synth(creating_txid, MLSC_ROOT_VOUT);
    Coin synth_coin;
    if (!cache.SpendCoin(synth, &synth_coin)) {
        // Entry missing — would indicate prior consensus bug or a tx that
        // somehow had no spendable outputs at AddCoins time. Either way, no
        // refcount to decrement.
        return;
    }
    const auto& spk = synth_coin.out.scriptPubKey;
    if (spk.empty() || spk[0] != rung::MLSC_SYNTHETIC_MARKER) {
        // Not a synthetic entry — should never happen at MLSC_ROOT_VOUT.
        // SpendCoin already removed it; do not re-add a corrupted entry.
        return;
    }
    if (spk.size() == MLSC_SYNTHETIC_PAYLOAD_SIZE_LEGACY) {
        // Legacy 33-byte entry (pre-v0.13 chainstate) — no refcount field.
        // Re-add unchanged so it persists like before. Operators on chains
        // with legacy entries should -reindex to upgrade to refcount form.
        cache.AddCoin(synth, std::move(synth_coin), /*possible_overwrite=*/true);
        return;
    }
    if (spk.size() != MLSC_SYNTHETIC_PAYLOAD_SIZE) {
        // Unknown payload size — leave deleted, do not re-add.
        return;
    }
    uint16_t refcount = static_cast<uint16_t>(spk[33]) |
                        (static_cast<uint16_t>(spk[34]) << 8);
    if (refcount <= 1) {
        // Last spend — leave the entry deleted. Chainstate cost recovered.
        // v2: surface the deleted root so the caller can persist it in undo
        // data for reorg recovery.
        if (deleted_root_out) {
            std::memcpy(deleted_root_out->data(), &spk[1], 32);
        }
        return;
    }
    refcount--;
    synth_coin.out.scriptPubKey[33] = static_cast<uint8_t>(refcount & 0xFF);
    synth_coin.out.scriptPubKey[34] = static_cast<uint8_t>((refcount >> 8) & 0xFF);
    cache.AddCoin(synth, std::move(synth_coin), /*possible_overwrite=*/true);
}

bool IncrementMLSCSyntheticRefcount(CCoinsViewCache& cache,
                                     const Txid& creating_txid,
                                     const uint256* recovery_root,
                                     int recovery_height)
{
    const COutPoint synth(creating_txid, MLSC_ROOT_VOUT);
    Coin synth_coin;
    if (!cache.SpendCoin(synth, &synth_coin)) {
        // Entry missing — deep reorg crossed a GC point. v2 (audit
        // 2026-05-03 F2): if a recovery root was provided (from undo
        // data), recreate the entry with refcount = 1 so subsequent
        // spends of any output from this creating tx find a valid root.
        // Without recovery, the disconnect would leave the chainstate
        // diverging from fresh-synced nodes (chain-split risk on
        // re-spend).
        if (recovery_root != nullptr) {
            CTxOut root_out;
            root_out.nValue = 0;
            root_out.scriptPubKey.resize(MLSC_SYNTHETIC_PAYLOAD_SIZE);
            root_out.scriptPubKey[0] = rung::MLSC_SYNTHETIC_MARKER;
            std::memcpy(&root_out.scriptPubKey[1], recovery_root->data(), 32);
            root_out.scriptPubKey[33] = 0x01; // refcount = 1, LE low byte
            root_out.scriptPubKey[34] = 0x00; // refcount = 1, LE high byte
            cache.AddCoin(synth, Coin(std::move(root_out), recovery_height, false),
                          /*possible_overwrite=*/true);
            return true;
        }
        return false;
    }
    const auto& spk = synth_coin.out.scriptPubKey;
    if (spk.empty() || spk[0] != rung::MLSC_SYNTHETIC_MARKER) {
        return false;
    }
    if (spk.size() == MLSC_SYNTHETIC_PAYLOAD_SIZE_LEGACY) {
        // Legacy 33-byte entry — no refcount, leave unchanged.
        cache.AddCoin(synth, std::move(synth_coin), /*possible_overwrite=*/true);
        return true;
    }
    if (spk.size() != MLSC_SYNTHETIC_PAYLOAD_SIZE) {
        return false;
    }
    uint16_t refcount = static_cast<uint16_t>(spk[33]) |
                        (static_cast<uint16_t>(spk[34]) << 8);
    refcount++;
    synth_coin.out.scriptPubKey[33] = static_cast<uint8_t>(refcount & 0xFF);
    synth_coin.out.scriptPubKey[34] = static_cast<uint8_t>((refcount >> 8) & 0xFF);
    cache.AddCoin(synth, std::move(synth_coin), /*possible_overwrite=*/true);
    return true;
}

bool CCoinsViewCache::SpendCoin(const COutPoint &outpoint, Coin* moveout) {
    CCoinsMap::iterator it = FetchCoin(outpoint);
    if (it == cacheCoins.end()) return false;
    cachedCoinsUsage -= it->second.coin.DynamicMemoryUsage();
    TRACEPOINT(utxocache, spent,
           outpoint.hash.data(),
           (uint32_t)outpoint.n,
           (uint32_t)it->second.coin.nHeight,
           (int64_t)it->second.coin.out.nValue,
           (bool)it->second.coin.IsCoinBase());
    if (moveout) {
        *moveout = std::move(it->second.coin);
    }
    if (it->second.IsFresh()) {
        cacheCoins.erase(it);
    } else {
        CCoinsCacheEntry::SetDirty(*it, m_sentinel);
        it->second.coin.Clear();
    }
    return true;
}

static const Coin coinEmpty;

const Coin& CCoinsViewCache::AccessCoin(const COutPoint &outpoint) const {
    CCoinsMap::const_iterator it = FetchCoin(outpoint);
    if (it == cacheCoins.end()) {
        return coinEmpty;
    } else {
        return it->second.coin;
    }
}

bool CCoinsViewCache::HaveCoin(const COutPoint &outpoint) const {
    CCoinsMap::const_iterator it = FetchCoin(outpoint);
    return (it != cacheCoins.end() && !it->second.coin.IsSpent());
}

bool CCoinsViewCache::HaveCoinInCache(const COutPoint &outpoint) const {
    CCoinsMap::const_iterator it = cacheCoins.find(outpoint);
    return (it != cacheCoins.end() && !it->second.coin.IsSpent());
}

uint256 CCoinsViewCache::GetBestBlock() const {
    if (hashBlock.IsNull())
        hashBlock = base->GetBestBlock();
    return hashBlock;
}

void CCoinsViewCache::SetBestBlock(const uint256 &hashBlockIn) {
    hashBlock = hashBlockIn;
}

bool CCoinsViewCache::BatchWrite(CoinsViewCacheCursor& cursor, const uint256 &hashBlockIn) {
    for (auto it{cursor.Begin()}; it != cursor.End(); it = cursor.NextAndMaybeErase(*it)) {
        // Ignore non-dirty entries (optimization).
        if (!it->second.IsDirty()) {
            continue;
        }
        CCoinsMap::iterator itUs = cacheCoins.find(it->first);
        if (itUs == cacheCoins.end()) {
            // The parent cache does not have an entry, while the child cache does.
            // We can ignore it if it's both spent and FRESH in the child
            if (!(it->second.IsFresh() && it->second.coin.IsSpent())) {
                // Create the coin in the parent cache, move the data up
                // and mark it as dirty.
                itUs = cacheCoins.try_emplace(it->first).first;
                CCoinsCacheEntry& entry{itUs->second};
                if (cursor.WillErase(*it)) {
                    // Since this entry will be erased,
                    // we can move the coin into us instead of copying it
                    entry.coin = std::move(it->second.coin);
                } else {
                    entry.coin = it->second.coin;
                }
                cachedCoinsUsage += entry.coin.DynamicMemoryUsage();
                CCoinsCacheEntry::SetDirty(*itUs, m_sentinel);
                // We can mark it FRESH in the parent if it was FRESH in the child
                // Otherwise it might have just been flushed from the parent's cache
                // and already exist in the grandparent
                if (it->second.IsFresh()) CCoinsCacheEntry::SetFresh(*itUs, m_sentinel);
            }
        } else {
            // Found the entry in the parent cache
            if (it->second.IsFresh() && !itUs->second.coin.IsSpent()) {
                // The coin was marked FRESH in the child cache, but the coin
                // exists in the parent cache. If this ever happens, it means
                // the FRESH flag was misapplied and there is a logic error in
                // the calling code.
                throw std::logic_error("FRESH flag misapplied to coin that exists in parent cache");
            }

            if (itUs->second.IsFresh() && it->second.coin.IsSpent()) {
                // The grandparent cache does not have an entry, and the coin
                // has been spent. We can just delete it from the parent cache.
                cachedCoinsUsage -= itUs->second.coin.DynamicMemoryUsage();
                cacheCoins.erase(itUs);
            } else {
                // A normal modification.
                cachedCoinsUsage -= itUs->second.coin.DynamicMemoryUsage();
                if (cursor.WillErase(*it)) {
                    // Since this entry will be erased,
                    // we can move the coin into us instead of copying it
                    itUs->second.coin = std::move(it->second.coin);
                } else {
                    itUs->second.coin = it->second.coin;
                }
                cachedCoinsUsage += itUs->second.coin.DynamicMemoryUsage();
                CCoinsCacheEntry::SetDirty(*itUs, m_sentinel);
                // NOTE: It isn't safe to mark the coin as FRESH in the parent
                // cache. If it already existed and was spent in the parent
                // cache then marking it FRESH would prevent that spentness
                // from being flushed to the grandparent.
            }
        }
    }
    hashBlock = hashBlockIn;
    return true;
}

bool CCoinsViewCache::Flush() {
    auto cursor{CoinsViewCacheCursor(cachedCoinsUsage, m_sentinel, cacheCoins, /*will_erase=*/true)};
    bool fOk = base->BatchWrite(cursor, hashBlock);
    if (fOk) {
        cacheCoins.clear();
        ReallocateCache();
    }
    cachedCoinsUsage = 0;
    return fOk;
}

bool CCoinsViewCache::Sync()
{
    auto cursor{CoinsViewCacheCursor(cachedCoinsUsage, m_sentinel, cacheCoins, /*will_erase=*/false)};
    bool fOk = base->BatchWrite(cursor, hashBlock);
    if (fOk) {
        if (m_sentinel.second.Next() != &m_sentinel) {
            /* BatchWrite must clear flags of all entries */
            throw std::logic_error("Not all unspent flagged entries were cleared");
        }
    }
    return fOk;
}

void CCoinsViewCache::Uncache(const COutPoint& hash)
{
    CCoinsMap::iterator it = cacheCoins.find(hash);
    if (it != cacheCoins.end() && !it->second.IsDirty() && !it->second.IsFresh()) {
        cachedCoinsUsage -= it->second.coin.DynamicMemoryUsage();
        TRACEPOINT(utxocache, uncache,
               hash.hash.data(),
               (uint32_t)hash.n,
               (uint32_t)it->second.coin.nHeight,
               (int64_t)it->second.coin.out.nValue,
               (bool)it->second.coin.IsCoinBase());
        cacheCoins.erase(it);
    }
}

unsigned int CCoinsViewCache::GetCacheSize() const {
    return cacheCoins.size();
}

bool CCoinsViewCache::HaveInputs(const CTransaction& tx) const
{
    if (!tx.IsCoinBase()) {
        for (unsigned int i = 0; i < tx.vin.size(); i++) {
            if (!HaveCoin(tx.vin[i].prevout)) {
                return false;
            }
        }
    }
    return true;
}

void CCoinsViewCache::ReallocateCache()
{
    // Cache should be empty when we're calling this.
    assert(cacheCoins.size() == 0);
    cacheCoins.~CCoinsMap();
    m_cache_coins_memory_resource.~CCoinsMapMemoryResource();
    ::new (&m_cache_coins_memory_resource) CCoinsMapMemoryResource{};
    ::new (&cacheCoins) CCoinsMap{0, SaltedOutpointHasher{/*deterministic=*/m_deterministic}, CCoinsMap::key_equal{}, &m_cache_coins_memory_resource};
}

void CCoinsViewCache::SanityCheck() const
{
    size_t recomputed_usage = 0;
    size_t count_flagged = 0;
    for (const auto& [_, entry] : cacheCoins) {
        unsigned attr = 0;
        if (entry.IsDirty()) attr |= 1;
        if (entry.IsFresh()) attr |= 2;
        if (entry.coin.IsSpent()) attr |= 4;
        // Only 5 combinations are possible.
        assert(attr != 2 && attr != 4 && attr != 7);

        // Recompute cachedCoinsUsage.
        recomputed_usage += entry.coin.DynamicMemoryUsage();

        // Count the number of entries we expect in the linked list.
        if (entry.IsDirty() || entry.IsFresh()) ++count_flagged;
    }
    // Iterate over the linked list of flagged entries.
    size_t count_linked = 0;
    for (auto it = m_sentinel.second.Next(); it != &m_sentinel; it = it->second.Next()) {
        // Verify linked list integrity.
        assert(it->second.Next()->second.Prev() == it);
        assert(it->second.Prev()->second.Next() == it);
        // Verify they are actually flagged.
        assert(it->second.IsDirty() || it->second.IsFresh());
        // Count the number of entries actually in the list.
        ++count_linked;
    }
    assert(count_linked == count_flagged);
    assert(recomputed_usage == cachedCoinsUsage);
}

static const size_t MIN_TRANSACTION_OUTPUT_WEIGHT = WITNESS_SCALE_FACTOR * ::GetSerializeSize(CTxOut());
static const size_t MAX_OUTPUTS_PER_BLOCK = MAX_BLOCK_WEIGHT / MIN_TRANSACTION_OUTPUT_WEIGHT;

const Coin& AccessByTxid(const CCoinsViewCache& view, const Txid& txid)
{
    COutPoint iter(txid, 0);
    while (iter.n < MAX_OUTPUTS_PER_BLOCK) {
        const Coin& alternate = view.AccessCoin(iter);
        if (!alternate.IsSpent()) return alternate;
        ++iter.n;
    }
    return coinEmpty;
}

template <typename ReturnType, typename Func>
static ReturnType ExecuteBackedWrapper(Func func, const std::vector<std::function<void()>>& err_callbacks)
{
    try {
        return func();
    } catch(const std::runtime_error& e) {
        for (const auto& f : err_callbacks) {
            f();
        }
        LogError("Error reading from database: %s\n", e.what());
        // Starting the shutdown sequence and returning false to the caller would be
        // interpreted as 'entry not found' (as opposed to unable to read data), and
        // could lead to invalid interpretation. Just exit immediately, as we can't
        // continue anyway, and all writes should be atomic.
        std::abort();
    }
}

std::optional<Coin> CCoinsViewErrorCatcher::GetCoin(const COutPoint& outpoint) const
{
    return ExecuteBackedWrapper<std::optional<Coin>>([&]() { return CCoinsViewBacked::GetCoin(outpoint); }, m_err_callbacks);
}

bool CCoinsViewErrorCatcher::HaveCoin(const COutPoint& outpoint) const
{
    return ExecuteBackedWrapper<bool>([&]() { return CCoinsViewBacked::HaveCoin(outpoint); }, m_err_callbacks);
}
