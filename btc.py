#!/usr/bin/python3

import ecdsa
import hashlib


class B58:
    b58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

    @staticmethod
    def base256decode(b: bytes) -> int:
        result = 0
        for c in b:
            result = result * 256 + c
        return result

    @staticmethod
    def base58encode(b: bytes) -> str:
        # Ref: https://asecuritysite.com/encryption/bit_keys
        n = B58.base256decode(b)
        result = ''
        while n > 0:
            result = B58.b58[n % 58] + result
            n = n // 58
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
        btc_private_key_suffixed = b'\x80' + btc_private_key
        hash1 = hashlib.sha256(btc_private_key_suffixed).digest()
        hash2 = hashlib.sha256(hash1).digest()
        btc_private_key_in_bytes = btc_private_key_suffixed + hash2[:4]
        btc_private_key_in_wif = B58.base58encode(btc_private_key_in_bytes)
        return btc_private_key_in_wif

    @staticmethod
    def compute_btc_address(btc_private_key: bytes) -> str:
        # Ref: https://asecuritysite.com/encryption/bit_keys
        sk = ecdsa.SigningKey.from_string(btc_private_key, curve=ecdsa.SECP256k1)
        vk = sk.get_verifying_key()
        vk_suffixed = b'\x04' + vk.to_string()

        ripemd160 = hashlib.new('ripemd160')
        ripemd160.update(hashlib.sha256(vk_suffixed).digest())
        vk_suffixed_hashed = ripemd160.digest()
        btc_address = B58.base58checkencode(0, vk_suffixed_hashed)
        return btc_address
