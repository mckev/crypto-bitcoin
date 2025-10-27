from lib.bip32 import Bip32
from lib.bip39 import Bip39
from lib.btc_address import BtcAddress


class TestHDWallets:
    PASSPHRASE = 'TREZOR'

    def test_bip_44(self):
        # https://learnmeabitcoin.com/technical/keys/hd-wallets/derivation-paths/  >  BIP 44
        mnemonic = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
        seed_bytes = Bip39.mnemonic_and_passphrase_to_seed(mnemonic, TestHDWallets.PASSPHRASE)
        assert seed_bytes.hex() == 'c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04'

        path = "m/44'/0'/0'/0/0"
        last_depth, parent_fingerprint, last_index, chain_code, private_int = Bip32.derive_from_path(seed_bytes, path)
        xprv = Bip32.serialize_xprv(last_depth, parent_fingerprint, last_index, chain_code, private_int)
        assert xprv == 'xprvA3SLGy5pCCjJn54ajX6CUDmKwP1f8pKPdETx3ZwnnnopwYpkgBsDsxm3JqNEkifWdVTpgBeE35rA93Kuu1MTy1WA8kf8iez7NwYFf7UXbd1'
        private_key_bytes = Bip32.deserialize_xprv(xprv)
        assert private_key_bytes.hex() == 'cdd74cbef2372344879b8a0aa8799435ff55bf5bde335638cb7a8d09fd0f9759'
        wif_str = BtcAddress.convert_private_key_into_wif(private_key_bytes)
        assert wif_str == 'L47qcNDdda3QMACwfisBm5XHrXvzTLd9H9Cxz3LBH2J8EBPFvMGo'
        btc_address_1, _, _ = BtcAddress.derive_public_addresses(private_key_bytes)
        assert btc_address_1 == '18unGcBDaY7Ciy9UbUCkAE8hV1wbDoMnm7'

        path = "m/44'/0'/0'/0/1"
        last_depth, parent_fingerprint, last_index, chain_code, private_int = Bip32.derive_from_path(seed_bytes, path)
        xprv = Bip32.serialize_xprv(last_depth, parent_fingerprint, last_index, chain_code, private_int)
        assert xprv == 'xprvA3SLGy5pCCjJrtLPCpe7b2RQZqCzHsbipXCYn1FxdHymovPVpMYKKojgJDrW4A3iHWSEU4kPbyVpPpWVovDVYZBk5tT49x3UHFWdDfQWrEs'
        private_key_bytes = Bip32.deserialize_xprv(xprv)
        assert private_key_bytes.hex() == 'eb9cbdfcfcdf6b682fae39cd133e587b6f238027ef541a1a28bb370edc085493'
        wif_str = BtcAddress.convert_private_key_into_wif(private_key_bytes)
        assert wif_str == 'L57i9t8wnUTEuMuqRJPbn5DJuzb5kMart79aSNQLzfBjuLgCve9x'
        btc_address_1, _, _ = BtcAddress.derive_public_addresses(private_key_bytes)
        assert btc_address_1 == '1AvFP97jqURXDMt7Jp2HUMpxrAg5HCF3Bs'

        path = "m/44'/0'/0'/0/2"
        last_depth, parent_fingerprint, last_index, chain_code, private_int = Bip32.derive_from_path(seed_bytes, path)
        xprv = Bip32.serialize_xprv(last_depth, parent_fingerprint, last_index, chain_code, private_int)
        assert xprv == 'xprvA3SLGy5pCCjJtiNiLnjpuKQ1bHUfrkREBVK5EuYAF4SUkb73N2utDDXsYxWBNf38FG8yZH146PVPAWNeUyauQ8opCiudrxJxFDvHQ6XeUAf'
        private_key_bytes = Bip32.deserialize_xprv(xprv)
        assert private_key_bytes.hex() == '07380ae85f2f5fa4a2c8ca8538d0c0d23c517b9f45c735406b0e3e90b69e66d6'
        wif_str = BtcAddress.convert_private_key_into_wif(private_key_bytes)
        assert wif_str == 'KwTk5Rg1EZCZDWrjHdbgRF2pr6GPzkY9vPdHGtnbx9Sk4tdrcQLp'
        btc_address_1, _, _ = BtcAddress.derive_public_addresses(private_key_bytes)
        assert btc_address_1 == '17iRiiA8haXYSpyPajoCwdsSz3DqDw6aX6'

        path = "m/44'/0'/0'/0/3"
        last_depth, parent_fingerprint, last_index, chain_code, private_int = Bip32.derive_from_path(seed_bytes, path)
        xprv = Bip32.serialize_xprv(last_depth, parent_fingerprint, last_index, chain_code, private_int)
        assert xprv == 'xprvA3SLGy5pCCjJwSUmEMpQcqiDqMyni9Ek6K2vGU1SwzH4DLQM2BYnSA8ykpSfrRjtf1JqTyUsWH5jrtzjAGYZDPmrqcUDDERnnoUg47fzdZ6'
        private_key_bytes = Bip32.deserialize_xprv(xprv)
        assert private_key_bytes.hex() == '86f858c1471b93377a9614b537302ba73771a9bb2bc3a6c49b2cf4d86a181509'
        wif_str = BtcAddress.convert_private_key_into_wif(private_key_bytes)
        assert wif_str == 'L1k5JypHTPs8NsEh7eXgUZsNW6WjxEa8fot3Per1x8v3ErBcwDNv'
        btc_address_1, _, _ = BtcAddress.derive_public_addresses(private_key_bytes)
        assert btc_address_1 == '12o9FAS1JEbHYmcbxd811HqKTeSKTHX51E'

    def test_bip_84(self):
        # https://learnmeabitcoin.com/technical/keys/hd-wallets/derivation-paths/  >  BIP 84
        mnemonic = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
        seed_bytes = Bip39.mnemonic_and_passphrase_to_seed(mnemonic, TestHDWallets.PASSPHRASE)
        assert seed_bytes.hex() == 'c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04'

        path = "m/84'/0'/0'/0/0"
        last_depth, parent_fingerprint, last_index, chain_code, private_int = Bip32.derive_from_path(seed_bytes, path)
        xprv = Bip32.serialize_xprv(last_depth, parent_fingerprint, last_index, chain_code, private_int)
        assert xprv == 'xprvA2oppAnZ3QZ8KxWFH8iqPvAN9t4Y2MSmfJxLrMs9DaqEYjbnPNXgtYDCARUPhNLTNAsVBfwT11QiKp7cyLwPUEx1pfaAVb3Se8b8HT2WxiW'
        private_key_bytes = Bip32.deserialize_xprv(xprv)
        assert private_key_bytes.hex() == '697e2dcb4c29ef4af9c937cd915c3872afc35217ad240794df09dd6fccdfb059'
        wif_str = BtcAddress.convert_private_key_into_wif(private_key_bytes)
        assert wif_str == 'KzkmvFYWQqevJNTWRRbC2tsicEU49LXRKrcdXRrVdXvisqRN8XtQ'
        _, _, btc_address_bc1q = BtcAddress.derive_public_addresses(private_key_bytes)
        assert btc_address_bc1q == 'bc1qv5rmq0kt9yz3pm36wvzct7p3x6mtgehjul0feu'

        path = "m/84'/0'/0'/0/1"
        last_depth, parent_fingerprint, last_index, chain_code, private_int = Bip32.derive_from_path(seed_bytes, path)
        xprv = Bip32.serialize_xprv(last_depth, parent_fingerprint, last_index, chain_code, private_int)
        assert xprv == 'xprvA2oppAnZ3QZ8NeeWUQomNigbhSn8t3SrNDdGRGm1uzasX3ZqKLKYi9UXaxS3JsrwUEbQ1HD6PvTavvfiBMYb9gTMhzPvTbtaG93QDhL6hq7'
        private_key_bytes = Bip32.deserialize_xprv(xprv)
        assert private_key_bytes.hex() == '335e5d073bc6ba3620c0cbfd6389d02e6fe5a642d15b2f12eb2855c9736e52de'
        wif_str = BtcAddress.convert_private_key_into_wif(private_key_bytes)
        assert wif_str == 'KxwZi3MBLWR72QMp2sqQh3PqsWoR6YNJB7kWtsFBrFcfWYqpRnKd'
        _, _, btc_address_bc1q = BtcAddress.derive_public_addresses(private_key_bytes)
        assert btc_address_bc1q == 'bc1qq4w9xyzsylpcy6hd76xr8pecxsvzqe743t2uj0'

        path = "m/84'/0'/0'/0/2"
        last_depth, parent_fingerprint, last_index, chain_code, private_int = Bip32.derive_from_path(seed_bytes, path)
        xprv = Bip32.serialize_xprv(last_depth, parent_fingerprint, last_index, chain_code, private_int)
        assert xprv == 'xprvA2oppAnZ3QZ8QXK4pboZ37bXSDzSRDRWFfmv8dwLWLkEP2Dgx2erNd12XKsyProCbG2Wj4yA2VunzYe3LbSQ1uqq1u5XBVeYiZ6D4VVLYJt'
        private_key_bytes = Bip32.deserialize_xprv(xprv)
        assert private_key_bytes.hex() == '7ac6ea250f858d9050ad65a647c16ee113f41efdcfd890e5f726d6188c3fdd46'
        wif_str = BtcAddress.convert_private_key_into_wif(private_key_bytes)
        assert wif_str == 'L1LNcBq8EEHJZAWkukrmNoxAnvGqPEhLMT1ST9qqZbrrkkik1mw1'
        _, _, btc_address_bc1q = BtcAddress.derive_public_addresses(private_key_bytes)
        assert btc_address_bc1q == 'bc1qjakxv37sq70e438vmtx0uw3cc0uesyatx5zx25'

        path = "m/84'/0'/0'/0/3"
        last_depth, parent_fingerprint, last_index, chain_code, private_int = Bip32.derive_from_path(seed_bytes, path)
        xprv = Bip32.serialize_xprv(last_depth, parent_fingerprint, last_index, chain_code, private_int)
        assert xprv == 'xprvA2oppAnZ3QZ8UBY2ms1dQ2RGrXGysb5fmpreYKCqaAZ7hyrgxYq48jR4gPMbR4D7KXPc4Yt7MLJszf45rp7Baq7x86sAgmdApKXbkEojMQD'
        private_key_bytes = Bip32.deserialize_xprv(xprv)
        assert private_key_bytes.hex() == '74953611e0dba2d908dcfb19937f39036ed1d516c01f5d5367f63de73d65fda8'
        wif_str = BtcAddress.convert_private_key_into_wif(private_key_bytes)
        assert wif_str == 'L18LFXEAJx4wn8fPE2RKumAWvLAaov6pZyCfE2DVX2ReouK7kkaz'
        _, _, btc_address_bc1q = BtcAddress.derive_public_addresses(private_key_bytes)
        assert btc_address_bc1q == 'bc1q648ez9vgqwn8frfff50klqryyy8l2m2fr4vu3c'

    def test_bip_84_youtube(self):
        # https://youtu.be/3ZKc6rY4hJc?si=QxKw4vQlHtEwkxfd&t=309 using Sparrow wallet
        mnemonic = 'diagram limit wink whip primary year ill multiply affair cycle slow captain indicate crouch brick auction happy envelope major mechanic illness lounge verify guide'
        passphrase = 'test'
        seed_bytes = Bip39.mnemonic_and_passphrase_to_seed(mnemonic, passphrase)

        # Receive Addresses
        path = "m/84'/0'/0'/0/0"
        last_depth, parent_fingerprint, last_index, chain_code, private_int = Bip32.derive_from_path(seed_bytes, path)
        xprv = Bip32.serialize_xprv(last_depth, parent_fingerprint, last_index, chain_code, private_int)
        private_key_bytes = Bip32.deserialize_xprv(xprv)
        _, _, btc_address_bc1q = BtcAddress.derive_public_addresses(private_key_bytes)
        assert btc_address_bc1q == 'bc1qvqznc77qtyvksh59hl36d4mu4ayflycntvgjj9'

        path = "m/84'/0'/0'/0/1"
        last_depth, parent_fingerprint, last_index, chain_code, private_int = Bip32.derive_from_path(seed_bytes, path)
        xprv = Bip32.serialize_xprv(last_depth, parent_fingerprint, last_index, chain_code, private_int)
        private_key_bytes = Bip32.deserialize_xprv(xprv)
        _, _, btc_address_bc1q = BtcAddress.derive_public_addresses(private_key_bytes)
        assert btc_address_bc1q == 'bc1q6gq8tcnglc0za25rd5e0w52vxjsycpr2gf5xm8'

        path = "m/84'/0'/0'/0/2"
        last_depth, parent_fingerprint, last_index, chain_code, private_int = Bip32.derive_from_path(seed_bytes, path)
        xprv = Bip32.serialize_xprv(last_depth, parent_fingerprint, last_index, chain_code, private_int)
        private_key_bytes = Bip32.deserialize_xprv(xprv)
        _, _, btc_address_bc1q = BtcAddress.derive_public_addresses(private_key_bytes)
        assert btc_address_bc1q == 'bc1qqxn454afkctsmxxl64umx8vfrjma6vw9cz09ss'

        path = "m/84'/0'/0'/0/3"
        last_depth, parent_fingerprint, last_index, chain_code, private_int = Bip32.derive_from_path(seed_bytes, path)
        xprv = Bip32.serialize_xprv(last_depth, parent_fingerprint, last_index, chain_code, private_int)
        private_key_bytes = Bip32.deserialize_xprv(xprv)
        _, _, btc_address_bc1q = BtcAddress.derive_public_addresses(private_key_bytes)
        assert btc_address_bc1q == 'bc1q7mlgmlq0qt3s09kurt8ae43nl0gdawuxyt2chl'

        path = "m/84'/0'/0'/0/13"
        last_depth, parent_fingerprint, last_index, chain_code, private_int = Bip32.derive_from_path(seed_bytes, path)
        xprv = Bip32.serialize_xprv(last_depth, parent_fingerprint, last_index, chain_code, private_int)
        private_key_bytes = Bip32.deserialize_xprv(xprv)
        _, _, btc_address_bc1q = BtcAddress.derive_public_addresses(private_key_bytes)
        assert btc_address_bc1q == 'bc1q33t9mtez9anagx3qm96qkd47fdaw6xljkv9h2a'

        # Change Addresses
        path = "m/84'/0'/0'/1/0"
        last_depth, parent_fingerprint, last_index, chain_code, private_int = Bip32.derive_from_path(seed_bytes, path)
        xprv = Bip32.serialize_xprv(last_depth, parent_fingerprint, last_index, chain_code, private_int)
        private_key_bytes = Bip32.deserialize_xprv(xprv)
        _, _, btc_address_bc1q = BtcAddress.derive_public_addresses(private_key_bytes)
        assert btc_address_bc1q == 'bc1qjphawgalq7xwycj2vym35x8twmd8wcz5hd4eng'

        path = "m/84'/0'/0'/1/1"
        last_depth, parent_fingerprint, last_index, chain_code, private_int = Bip32.derive_from_path(seed_bytes, path)
        xprv = Bip32.serialize_xprv(last_depth, parent_fingerprint, last_index, chain_code, private_int)
        private_key_bytes = Bip32.deserialize_xprv(xprv)
        _, _, btc_address_bc1q = BtcAddress.derive_public_addresses(private_key_bytes)
        assert btc_address_bc1q == 'bc1qvjjstzdn6xamclwmqtzg5c4wmzfjyjv2d0an0c'

        path = "m/84'/0'/0'/1/2"
        last_depth, parent_fingerprint, last_index, chain_code, private_int = Bip32.derive_from_path(seed_bytes, path)
        xprv = Bip32.serialize_xprv(last_depth, parent_fingerprint, last_index, chain_code, private_int)
        private_key_bytes = Bip32.deserialize_xprv(xprv)
        _, _, btc_address_bc1q = BtcAddress.derive_public_addresses(private_key_bytes)
        assert btc_address_bc1q == 'bc1qnrz8rkhr40jc3vgv83jfqj56gxyejxtjrycwt4'

        path = "m/84'/0'/0'/1/3"
        last_depth, parent_fingerprint, last_index, chain_code, private_int = Bip32.derive_from_path(seed_bytes, path)
        xprv = Bip32.serialize_xprv(last_depth, parent_fingerprint, last_index, chain_code, private_int)
        private_key_bytes = Bip32.deserialize_xprv(xprv)
        _, _, btc_address_bc1q = BtcAddress.derive_public_addresses(private_key_bytes)
        assert btc_address_bc1q == 'bc1qerz8j6p6uczy8ejahdwfyn4rpd7v2v08jpvj97'

        path = "m/84'/0'/0'/1/13"
        last_depth, parent_fingerprint, last_index, chain_code, private_int = Bip32.derive_from_path(seed_bytes, path)
        xprv = Bip32.serialize_xprv(last_depth, parent_fingerprint, last_index, chain_code, private_int)
        private_key_bytes = Bip32.deserialize_xprv(xprv)
        _, _, btc_address_bc1q = BtcAddress.derive_public_addresses(private_key_bytes)
        assert btc_address_bc1q == 'bc1qtd4hndqrp9rhg4rnc98chen3pwfwu0q9df8j32'
