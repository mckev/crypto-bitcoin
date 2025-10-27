# BIP 0032 : HD Wallets
# https://en.bitcoin.it/wiki/BIP_0032

import hashlib
import hmac
import struct

import base58
import ecdsa


class Bip32:

    N = ecdsa.SECP256k1.order

    @staticmethod
    def sha256(b: bytes) -> bytes:
        return hashlib.sha256(b).digest()

    @staticmethod
    def ripemd160(b: bytes) -> bytes:
        return hashlib.new('ripemd160', b).digest()

    @staticmethod
    def int_to_bytes(i: int, length: int) -> bytes:
        return i.to_bytes(length, 'big')

    @staticmethod
    def bytes_to_int(b: bytes) -> int:
        return int.from_bytes(b, 'big')

    @staticmethod
    def fingerprint_from_private(private_int: int):
        public = ecdsa.SigningKey.from_secret_exponent(private_int, curve=ecdsa.SECP256k1).verifying_key
        public_bytes = public.to_string('compressed')
        private_fingerprint = Bip32.ripemd160(Bip32.sha256(public_bytes))[:4]
        return private_fingerprint

    @staticmethod
    def master_key_from_seed(seed_bytes: bytes):
        if not (16 <= len(seed_bytes) <= 64):
            raise ValueError('Seed length must be between 16 and 64 bytes for BIP32')
        I = hmac.new(b'Bitcoin seed', seed_bytes, hashlib.sha512).digest()
        IL, IR = I[:32], I[32:]
        master_private_int = Bip32.bytes_to_int(IL)
        if master_private_int == 0 or master_private_int >= Bip32.N:
            raise ValueError('Generated an invalid master key; very improbable. Please choose another seed.')
        master_chain_code = IR
        assert len(master_chain_code) == 32
        return master_private_int, master_chain_code

    @staticmethod
    def parse_path(path: str):
        if path == 'm':
            return []
        if not path.startswith('m/'):
            raise ValueError('Path must start with "m/"')
        elements = path.lstrip('m/').split('/')
        result = []
        for element in elements:
            if element.endswith("'") or element.endswith('h') or element.endswith('H'):
                index = int(element[:-1])
                result.append(0x80000000 | index)
            else:
                index = int(element)
                result.append(index)
        return result

    @staticmethod
    def derive_child_key(parent_private_int: int, parent_chain_code: bytes, index: int):
        assert 0 <= index < 2**32
        if index >= 0x80000000:
            # Hardened
            data = b'\x00' + Bip32.int_to_bytes(parent_private_int, 32) + struct.pack('>I', index)
        else:
            # Non-hardened
            public = ecdsa.SigningKey.from_secret_exponent(parent_private_int, curve=ecdsa.SECP256k1).verifying_key
            public_bytes = public.to_string('compressed')
            data = public_bytes + struct.pack('>I', index)
        I = hmac.new(parent_chain_code, data, hashlib.sha512).digest()
        IL, IR = I[:32], I[32:]
        child_private_int = (Bip32.bytes_to_int(IL) + parent_private_int) % Bip32.N
        if child_private_int == 0 or Bip32.bytes_to_int(IL) >= Bip32.N:
            # as BIP32: invalid, should proceed with next index; here we raise
            raise ValueError('Generated an invalid child key; very improbable. Please choose a different index')
        child_chain_code = IR
        assert len(child_chain_code) == 32
        return child_private_int, child_chain_code

    @staticmethod
    def derive_from_path(seed_bytes: bytes, path: str):
        private_fingerprint = b'\x00\x00\x00\x00'
        private_int, chain_code = Bip32.master_key_from_seed(seed_bytes)
        index = 0
        depth = 0
        for index in Bip32.parse_path(path):
            private_fingerprint = Bip32.fingerprint_from_private(private_int)
            private_int, chain_code = Bip32.derive_child_key(private_int, chain_code, index)
            depth += 1
        return depth, private_fingerprint, index, chain_code, private_int

    @staticmethod
    def serialize_xprv(last_depth, private_fingerprint, last_index, chain_code, private_int):
        version = bytes.fromhex('0488ADE4')                 # xprv mainnet
        data = (
            version +
            Bip32.int_to_bytes(last_depth, 1) +
            private_fingerprint +
            struct.pack('>I', last_index) +
            chain_code +
            b'\x00' + Bip32.int_to_bytes(private_int, 32)
        )
        checksum = Bip32.sha256(Bip32.sha256(data))[:4]
        return base58.b58encode(data + checksum).decode()

    @staticmethod
    def serialize_xpub(last_depth, private_fingerprint, last_index, chain_code, private_int):
        version = bytes.fromhex('0488B21E')                 # xpub mainnet
        public = ecdsa.SigningKey.from_secret_exponent(private_int, curve=ecdsa.SECP256k1).verifying_key
        public_bytes = public.to_string('compressed')
        data = (
            version +
            Bip32.int_to_bytes(last_depth, 1) +
            private_fingerprint +
            struct.pack('>I', last_index) +
            chain_code +
            public_bytes
        )
        checksum = Bip32.sha256(Bip32.sha256(data))[:4]
        return base58.b58encode(data + checksum).decode()
