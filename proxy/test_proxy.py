#!/usr/bin/env python3
"""Unit tests for ladder_proxy.py helper functions.

Tests _derive_path, _privkey_to_wif, _ripemd160, _b58encode, _b58decode.
Uses known test vectors from BIP32 and Bitcoin address generation.

Run: python3 -m pytest proxy/test_proxy.py -v
"""

import hashlib
import struct
import sys
import unittest
from pathlib import Path

# Import helpers directly from ladder_proxy
sys.path.insert(0, str(Path(__file__).resolve().parent))
from ladder_proxy import (
    _b58encode,
    _b58decode,
    _b58decode_check,
    _derive_child,
    _derive_path,
    _privkey_to_wif,
    _ripemd160,
    _B58_ALPHABET,
    _SECP256K1_N,
)


class TestBase58(unittest.TestCase):
    """Verify base58 encode/decode roundtrips."""

    def test_roundtrip_simple(self):
        data = bytes.fromhex("0000010966776006953D5567439E5E39F86A0D273BEED61967F6")
        encoded = _b58encode(data)
        decoded = _b58decode(encoded)
        self.assertEqual(decoded, data)

    def test_leading_zeros(self):
        data = b'\x00\x00\x00hello'
        encoded = _b58encode(data)
        self.assertTrue(encoded.startswith('111'))
        decoded = _b58decode(encoded)
        self.assertEqual(decoded, data)

    def test_empty(self):
        self.assertEqual(_b58encode(b''), '')


class TestPrivkeyToWif(unittest.TestCase):
    """Verify WIF encoding matches known test vectors."""

    def test_testnet_wif(self):
        # Known testnet privkey → WIF
        privkey = bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000001")
        wif = _privkey_to_wif(privkey, testnet=True)
        # Testnet compressed WIF starts with 'c'
        self.assertTrue(wif.startswith('c'), f"Testnet WIF should start with 'c', got {wif[:5]}")
        # Verify checksum by decoding
        decoded = _b58decode(wif)
        payload, checksum = decoded[:-4], decoded[-4:]
        expected_ck = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
        self.assertEqual(checksum, expected_ck, "WIF checksum mismatch")

    def test_mainnet_wif(self):
        privkey = bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000001")
        wif = _privkey_to_wif(privkey, testnet=False)
        # Mainnet compressed WIF starts with 'K' or 'L'
        self.assertIn(wif[0], ('K', 'L'), f"Mainnet WIF should start with K or L, got {wif[0]}")

    def test_wif_length(self):
        privkey = bytes(range(1, 33))  # 32 non-zero bytes
        wif = _privkey_to_wif(privkey, testnet=True)
        # Compressed WIF is 52 characters
        self.assertEqual(len(wif), 52, f"WIF length should be 52, got {len(wif)}")


class TestDerivePath(unittest.TestCase):
    """Verify BIP32 key derivation against known vectors."""

    # BIP32 Test Vector 1: seed 000102030405060708090a0b0c0d0e0f
    SEED = bytes.fromhex("000102030405060708090a0b0c0d0e0f")

    @classmethod
    def setUpClass(cls):
        # Derive master key from seed (BIP32 spec)
        import hmac as hmac_mod
        I = hmac_mod.new(b"Bitcoin seed", cls.SEED, hashlib.sha512).digest()
        cls.master_privkey = I[:32]
        cls.master_chaincode = I[32:]

    def test_master_key(self):
        # BIP32 test vector 1 master private key
        expected = "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35"
        self.assertEqual(self.master_privkey.hex(), expected)

    def test_derive_hardened_child(self):
        # m/0' from BIP32 test vector 1
        child_key, child_chain = _derive_child(
            self.master_privkey, self.master_chaincode, 0, hardened=True
        )
        expected_key = "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea"
        self.assertEqual(child_key.hex(), expected_key)

    def test_derive_path_m_0h(self):
        child_key = _derive_path(self.master_privkey, self.master_chaincode, "m/0'")
        expected = "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea"
        self.assertEqual(child_key.hex(), expected)

    def test_derive_deep_path(self):
        # m/0'/1 from BIP32 test vector 1
        child_key = _derive_path(self.master_privkey, self.master_chaincode, "m/0'/1")
        expected = "3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368"
        self.assertEqual(child_key.hex(), expected)


class TestRipemd160(unittest.TestCase):
    """Verify pure-Python RIPEMD-160 against known test vectors."""

    def test_empty_string(self):
        result = _ripemd160(b"")
        self.assertEqual(result.hex(), "9c1185a5c5e9fc54612808977ee8f548b2258d31")

    def test_abc(self):
        result = _ripemd160(b"abc")
        self.assertEqual(result.hex(), "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc")

    def test_hash160(self):
        """Test HASH160 = RIPEMD160(SHA256(x)) for a known pubkey."""
        # Compressed pubkey for privkey=1
        pubkey = bytes.fromhex(
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        )
        sha = hashlib.sha256(pubkey).digest()
        h160 = _ripemd160(sha)
        expected = "751e76e8199196d454941c45d1b3a323f1433bd6"
        self.assertEqual(h160.hex(), expected)

    def test_longer_input(self):
        result = _ripemd160(b"message digest")
        self.assertEqual(result.hex(), "5d0689ef49d2fae572b881b123a85ffa21595f36")

    def test_alphabet(self):
        result = _ripemd160(b"abcdefghijklmnopqrstuvwxyz")
        self.assertEqual(result.hex(), "f71c27109c692c1b56bbdceb5b9d2865b3708dbc")


if __name__ == '__main__':
    unittest.main(verbosity=2)
