#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Copyright (c) 2026 defenwycke
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Descriptor parser <-> formatter round-trip property test.

For every descriptor `d` in DESCRIPTORS:

    1. parse d           -> conditions_hex_1, mlsc_root_1, pubkeys_hex
    2. format hex_1, pubkeys_hex, keys -> descriptor_2
    3. parse descriptor_2 -> conditions_hex_3, mlsc_root_3

Properties asserted:
    mlsc_root_1     == mlsc_root_3
    conditions_hex_1 == conditions_hex_3

Catches asymmetric bugs between parser and printer:
  - F18 (anchor variants all rendered as bare family name and lost
    their parameter -> step-3 reparse drifted from step-1)
  - F19 (formatter emitted non-reparseable @? for pubkey-bearing
    blocks -> step-3 failed entirely; fixed by threading parseladder's
    pubkeys_hex back through formatladder)

Step-2 also passes the alias map so any leaf whose pubkey matches an
alias renders as @alias rather than as an 8-char hex prefix; both
forms reparse to the same conditions, so the round-trip property holds
either way, but the alias-aware path exercises the reverse-lookup code.
"""

import json

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


KEYS = {
    "alice": "02" + "11" * 32,
    "bob": "02" + "22" * 32,
    "carol": "02" + "33" * 32,
}

DESCRIPTORS = [
    # Sig family — exercises the F19 key-aware printer path.
    "ladder(sig(@alice))",
    "ladder(multisig(2, @alice, @bob, @carol))",
    "ladder(adaptor_sig(@alice))",
    "ladder(musig_threshold(2, @alice, @bob))",
    # Timelock family
    "ladder(csv(144))",
    "ladder(cltv(0))",
    "ladder(csv_time(512))",
    "ladder(cltv_time(1700000000))",
    # Hash family
    "ladder(tagged_hash(" + "aa" * 32 + ", " + "bb" * 32 + "))",
    "ladder(hash_guarded(" + "cc" * 32 + "))",
    # Covenant family
    "ladder(ctv(" + "dd" * 32 + "))",
    "ladder(amount_lock(10000, 1000000000))",
    # Recursion family
    "ladder(recurse_same(5))",
    "ladder(recurse_until(1000000))",
    "ladder(recurse_count(10))",
    "ladder(recurse_split(4, 10000))",
    # Anchor family — F18 regression: each variant must render with
    # its own name AND its parameter, not the bare family name.
    "ladder(anchor(10))",
    "ladder(anchor_channel(1))",
    # F22 regression: anchor_fee was falling through the formatter's
    # default branch and producing a non-reparseable "anchor_fee(...)"
    # placeholder. Now has an explicit case that emits all 4 numerics.
    "ladder(anchor_fee(@alice, @bob, 1000, 100000, 400, 12345))",
    # Compound family — pubkey + numeric.
    "ladder(timelocked_sig(@alice, 144))",
    "ladder(cltv_sig(@alice, 0))",
    # F23 regression: blocks that take TWO pubkeys must keep them in
    # parser-order. Unspecified-evaluation-order on chained operator+
    # would silently swap them.
    "ladder(vault_lock(@alice, @bob, 144))",
    # F20 continuation: PTLC parser dropped v0.6 second pubkey, so
    # formatter must emit single-pubkey form.
    "ladder(ptlc(@alice, 144))",
    # F24 fixed: htlc and hash_sig accept either a preimage (gets SHA256'd)
    # or a `h:HASH256` form (stored verbatim). Formatter always emits the
    # `h:` form so parse->format->parse round-trips. Both forms exercised
    # so the parser branches stay covered.
    "ladder(htlc(@alice, @bob, " + "ee" * 32 + ", 144))",          # preimage form
    "ladder(htlc(@alice, @bob, h:" + "4d" * 32 + ", 144))",        # h: form
    "ladder(hash_sig(@alice, " + "ee" * 32 + "))",                  # preimage form
    "ladder(hash_sig(@alice, h:" + "ab" * 32 + "))",               # h: form
    # Governance
    "ladder(weight_limit(100000))",
    "ladder(input_count(1, 10))",
    "ladder(output_count(1, 10))",
    "ladder(relative_value(1, 2))",
    "ladder(epoch_gate(65536, 131072))",
    # Compound — and() within a single rung. F22 territory: the wrapper
    # emission has to round-trip too, not just the leaf blocks.
    "ladder(and(sig(@alice), csv(144)))",
    "ladder(and(sig(@alice), cltv(0), amount_lock(10000, 1000000000)))",
    "ladder(and(multisig(2, @alice, @bob), csv(72)))",
    # Multi-rung — or() wraps multiple rungs.
    "ladder(or(sig(@alice), sig(@bob)))",
    "ladder(or(and(sig(@alice), csv(144)), sig(@bob)))",
    "ladder(or(sig(@alice), and(sig(@bob), cltv(0))))",
    # Bigger compound: 3-rung or() with one and() rung.
    "ladder(or(sig(@alice), sig(@bob), and(sig(@carol), csv(7))))",
]


class RungDescriptorRoundtrip(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.noban_tx_relay = True

    def run_test(self):
        node = self.nodes[0]
        keys_json = json.dumps(KEYS)

        for d in DESCRIPTORS:
            r1 = node.parseladder(d, keys_json)
            cond_hex_1 = r1["conditions_hex"]
            mlsc_root_1 = r1["mlsc_root"]
            pubkeys_hex = r1["pubkeys_hex"]
            merkle_pks_hex = r1["merkle_pubkeys_hex"]

            formatted = node.formatladder(
                cond_hex_1, pubkeys_hex, keys_json, merkle_pks_hex
            )["descriptor"]

            r3 = node.parseladder(formatted, keys_json)
            assert_equal(r3["mlsc_root"], mlsc_root_1)
            assert_equal(r3["conditions_hex"], cond_hex_1)

            self.log.info(
                "round-trip OK: %-50s -> %s", d[:50], formatted[:60]
            )


if __name__ == "__main__":
    RungDescriptorRoundtrip(__file__).main()
