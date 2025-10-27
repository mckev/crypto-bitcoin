import hashlib

import base58           # pip3 install --break-system-packages base58
import bech32           # pip3 install --break-system-packages bech32
import ecdsa            # pip3 install --break-system-packages ecdsa


class BtcAddress:
    @staticmethod
    def sha256(b: bytes) -> bytes:
        return hashlib.sha256(b).digest()

    @staticmethod
    def ripemd160(b: bytes) -> bytes:
        return hashlib.new('ripemd160', b).digest()

    @staticmethod
    def convert_private_key_into_wif(private_key_bytes: bytes) -> str:
        assert len(private_key_bytes) == 32
        private_key_int = int.from_bytes(private_key_bytes, 'big')
        print(f'Private Key (decimal): {private_key_int}')
        private_key_hex = private_key_bytes.hex()
        print(f'Private Key (hex): {private_key_hex}')
        # https://en.bitcoin.it/wiki/Wallet_import_format (0x80 for mainnet)
        checksum = BtcAddress.sha256(BtcAddress.sha256(b'\x80' + private_key_bytes + b'\x01'))[:4]
        # 0x01 suffix for WIF compressed
        wif_str = base58.b58encode(b'\x80' + private_key_bytes + b'\x01' + checksum).decode()
        print(f'Private Key (WIF compressed): {wif_str}')
        print()
        return wif_str

    @staticmethod
    def convert_wif_into_private_key(wif_str: str) -> bytes:
        wif_bytes = base58.b58decode(wif_str)
        assert wif_bytes[0] == 0x80
        checksum = BtcAddress.sha256(BtcAddress.sha256(wif_bytes[:-4]))[:4]
        assert checksum == wif_bytes[-4:]
        private_key_bytes = wif_bytes[1:32+1]
        assert len(private_key_bytes) == 32
        return private_key_bytes

    @staticmethod
    def derive_public_addresses(private_key_bytes: bytes):
        # You can use https://www.blockchain.com/explorer/addresses/btc/<address> to verify

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

        # 3. Create P2PKH / Pay-to-Public-Key-Hash / Legacy Bitcoin address
        #       - Step 1: Hash of the public key (SHA-256 then RIPEMD-160)
        hashed_pubkey = BtcAddress.ripemd160(BtcAddress.sha256(public_key_bytes))
        #       - Step 2: Add version byte (0x00 for mainnet)
        versioned_payload = b'\x00' + hashed_pubkey
        #       - Step 3: Create checksum (double SHA-256)
        checksum = BtcAddress.sha256(BtcAddress.sha256(versioned_payload))[:4]
        #       - Step 4: Combine and encode with base58
        #    Ref: https://learnmeabitcoin.com/technical/script/p2pkh/
        btc_address_1 = base58.b58encode(versioned_payload + checksum).decode()
        assert btc_address_1.startswith('1')
        print(f'Bitcoin Address 1 (legacy): {btc_address_1}')
        print()

        # 4. Compress the public key
        pubkey_bytes = vk.to_string()
        x = pubkey_bytes[:32]
        y = pubkey_bytes[32:]
        prefix = b'\x02' if int.from_bytes(y, 'big') % 2 == 0 else b'\x03'
        compressed_pubkey = prefix + x
        print(f'Compressed Public Key (hex): {compressed_pubkey.hex()}')
        hashed_compressed_pubkey = BtcAddress.ripemd160(BtcAddress.sha256(compressed_pubkey))

        # 5. Create P2SH / Pay-to-Script-Hash Bitcoin address
        redeem_script = b'\x00\x14' + hashed_compressed_pubkey
        redeem_script_hash = BtcAddress.ripemd160(BtcAddress.sha256(redeem_script))
        versioned_payload = b'\x05' + redeem_script_hash
        checksum = BtcAddress.sha256(BtcAddress.sha256(versioned_payload))[:4]
        btc_address_3 = base58.b58encode(versioned_payload + checksum).decode()
        assert len(btc_address_3) == 34
        assert btc_address_3.startswith('3')
        print(f'Bitcoin Address 3: {btc_address_3}')

        # 6. Create P2WPKH / Pay-to-Witness-Public-Key-Hash / Native Segwit Bitcoin address
        witness_version = 0
        witness_program = bech32.convertbits(hashed_compressed_pubkey, 8, 5, True)
        btc_address_bc1q = bech32.bech32_encode('bc', [witness_version] + witness_program)
        assert len(btc_address_bc1q) == 42
        assert btc_address_bc1q.startswith('bc1q')
        print(f'Bitcoin Address bc1q: {btc_address_bc1q}')

        return btc_address_1, btc_address_3, btc_address_bc1q
