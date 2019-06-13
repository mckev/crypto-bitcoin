#!/usr/bin/python3

import ecdsa
import hashlib


class B58:
    b58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

    @staticmethod
    def base58encode(b: bytes) -> str:
        # Ref: https://asecuritysite.com/encryption/bit_keys
        # Convert into number
        n = 0
        for c in b:
            n = n * 256 + c
        # Convert number into base-58
        result = ''
        while n > 0:
            result = B58.b58[n % 58] + result
            n = n // 58
        return result

    @staticmethod
    def base58decode(s: str) -> bytes:
        # Convert into number
        n = 0
        for ch in s:
            c = B58.b58.index(ch)
            n = n * 58 + c
        # Convert number into base-256
        result = b''
        while n > 0:
            result = bytes([n % 256]) + result
            n = n // 256
        return result

    @staticmethod
    def count_leading_chars(b: bytes, ch: int) -> int:
        count = 0
        for c in b:
            if c == ch:
                count += 1
            else:
                break
        return count

    @staticmethod
    def base58checkencode(version: int, payload: bytes) -> str:
        s = bytes([version]) + payload
        checksum = hashlib.sha256(hashlib.sha256(s).digest()).digest()[0:4]
        result = s + checksum
        leading_zeros = B58.count_leading_chars(result, 0)
        return '1' * leading_zeros + B58.base58encode(result)


class BTC:

    @staticmethod
    def convert_btc_private_key_into_wif(btc_private_key: bytes) -> str:
        # Refs:
        #    https://en.bitcoin.it/wiki/Wallet_import_format
        #    https://gobittest.appspot.com/PrivateKey
        btc_private_key_prefixed = b'\x80' + btc_private_key
        hash1 = hashlib.sha256(btc_private_key_prefixed).digest()
        hash2 = hashlib.sha256(hash1).digest()
        btc_private_key_in_bytes = btc_private_key_prefixed + hash2[:4]
        btc_private_key_in_wif = B58.base58encode(btc_private_key_in_bytes)
        return btc_private_key_in_wif

    @staticmethod
    def convert_btc_wif_into_private_key(btc_private_key_in_wif: str) -> bytes:
        btc_private_key_in_bytes = B58.base58decode(btc_private_key_in_wif)
        # return btc_private_key_in_bytes[1:-4]
        assert btc_private_key_in_bytes[0] == 0x80
        hash = btc_private_key_in_bytes[-4:]
        btc_private_key_prefixed = btc_private_key_in_bytes[:-4]
        hash1 = hashlib.sha256(btc_private_key_prefixed).digest()
        hash2 = hashlib.sha256(hash1).digest()
        assert hash == hash2[:4]
        btc_private_key = btc_private_key_prefixed[1:]
        return btc_private_key

    @staticmethod
    def compute_btc_address(btc_private_key: bytes) -> str:
        # Ref: https://asecuritysite.com/encryption/bit_keys
        sk = ecdsa.SigningKey.from_string(btc_private_key, curve=ecdsa.SECP256k1)
        vk = sk.get_verifying_key()
        vk_prefixed = b'\x04' + vk.to_string()

        ripemd160 = hashlib.new('ripemd160')
        ripemd160.update(hashlib.sha256(vk_prefixed).digest())
        vk_prefixed_hashed = ripemd160.digest()
        btc_address = B58.base58checkencode(0, vk_prefixed_hashed)
        return btc_address
