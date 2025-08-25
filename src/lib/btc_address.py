import hashlib

import base58           # pip3 install --break-system-packages base58
import bech32           # pip3 install --break-system-packages bech32
import ecdsa            # pip3 install --break-system-packages ecdsa


class BtcAddress:

    @staticmethod
    def convert_private_key_into_wif(private_key_bytes: bytes):
        assert len(private_key_bytes) == 32
        private_key_int = int.from_bytes(private_key_bytes, 'big')
        print(f'Private Key (decimal): {private_key_int}')
        private_key_hex = private_key_bytes.hex()
        print(f'Private Key (hex): {private_key_hex}')
        # https://en.bitcoin.it/wiki/Wallet_import_format (0x80 for mainnet)
        checksum = hashlib.sha256(hashlib.sha256(b'\x80' + private_key_bytes + b'\x01').digest()).digest()[:4]
        wif_compressed = base58.b58encode(b'\x80' + private_key_bytes + b'\x01' + checksum).decode()
        print(f'Private Key (WIF compressed): {wif_compressed}')
        print()
        return wif_compressed

    @staticmethod
    def derive_public_address(private_key_bytes: bytes):
        # 1. 256-bit private key
        assert len(private_key_bytes) == 32

        # 2. Generate public key using secp256k1
        sk = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1)
        vk = sk.get_verifying_key()
        public_key_bytes = b'\x04' + vk.to_string()
        public_key_int = int.from_bytes(public_key_bytes)
        print(f'Public Key (decimal): {public_key_int}')
        public_key_hex = public_key_bytes.hex()
        print(f'Public Key (hex): {public_key_hex}')
        print()

        # 3. Create Legacy (P2PKH) Bitcoin address
        #       - Step 1: Hash of the public key (SHA-256 then RIPEMD-160)
        sha256_hash = hashlib.sha256(public_key_bytes).digest()
        hashed_pubkey = hashlib.new('ripemd160', sha256_hash).digest()
        #       - Step 2: Add version byte (0x00 for mainnet)
        versioned_payload = b'\x00' + hashed_pubkey
        #       - Step 3: Create checksum (double SHA-256)
        checksum = hashlib.sha256(hashlib.sha256(versioned_payload).digest()).digest()[:4]
        #       - Step 4: Combine and encode with base58
        full_payload = versioned_payload + checksum
        btc_address_legacy = base58.b58encode(full_payload).decode()
        print(f'Bitcoin Address (Legacy): {btc_address_legacy}')
        print()

        # 4. Create Segwit (P2WPKH) Bitcoin address
        #       - Step 1: Compress the public key (required for Segwit)
        pubkey_bytes = vk.to_string()
        x = pubkey_bytes[:32]
        y = pubkey_bytes[32:]
        prefix = b'\x03' if int.from_bytes(y, 'big') % 2 else b'\x02'
        compressed_pubkey = prefix + x
        print(f'Compressed Public Key (hex): {compressed_pubkey.hex()}')
        #       - Step 2: Hash of the compressed public key (SHA-256 then RIPEMD-160)
        sha256_hash = hashlib.sha256(compressed_pubkey).digest()
        hashed_pubkey = hashlib.new('ripemd160', sha256_hash).digest()
        #       - Step 3: Create Bitcoin address (P2WPKH - witness version 0)
        #                 You can use https://www.blockchain.com/explorer/addresses/btc/<address> to verify
        witness_version = 0
        witness_program = bech32.convertbits(hashed_pubkey, 8, 5, True)
        btc_address_native_segwit = bech32.bech32_encode('bc', [witness_version] + witness_program)
        print(f'Bitcoin Address (Native Segwit): {btc_address_native_segwit}')

        return btc_address_legacy, btc_address_native_segwit
