import hashlib

import ecdsa

from lib.btc_address import BtcAddress


class TestBtcAddress:

    def test_convert_private_key_into_wif(self):
        # Ref: https://learnmeabitcoin.com/technical/keys/private-key/wif/
        private_key_bytes = bytes.fromhex('353acdd20da43ec797e9d9ce5ec2d2d4f361855d51a76504611521648c5d74b3')
        wif_str = BtcAddress.convert_private_key_into_wif(private_key_bytes)
        assert wif_str == 'Ky1BY5QkB6xb3iQQjJQmVcvqc6mkLBaZTW1xCWpf91aFGBh1kyQ7'

        private_key_bytes = bytes.fromhex('7da2fdb47a93e15c8ff65315e4b9786a49b3fe69bd38a2cea3e82fae0ae5cc5f')
        wif_str = BtcAddress.convert_private_key_into_wif(private_key_bytes)
        assert wif_str == 'L1Rw26ZuhBqguYDSi77zAxyfHUZ2H1JAQunf3TEbxyfcBDjUvBse'

    def test_convert_wif_into_private_key(self):
        wif_str = 'Ky1BY5QkB6xb3iQQjJQmVcvqc6mkLBaZTW1xCWpf91aFGBh1kyQ7'
        private_key_bytes = BtcAddress.convert_wif_into_private_key(wif_str)
        assert private_key_bytes == bytes.fromhex('353acdd20da43ec797e9d9ce5ec2d2d4f361855d51a76504611521648c5d74b3')

        wif_str = 'L1Rw26ZuhBqguYDSi77zAxyfHUZ2H1JAQunf3TEbxyfcBDjUvBse'
        private_key_bytes = BtcAddress.convert_wif_into_private_key(wif_str)
        assert private_key_bytes == bytes.fromhex('7da2fdb47a93e15c8ff65315e4b9786a49b3fe69bd38a2cea3e82fae0ae5cc5f')

    def test_derive_public_addresses_01(self):
        # Ref: https://www.palkeo.com/en/blog/stealing-bitcoin.html
        private_key_bytes = bytes.fromhex('0000000000000000000000000000000000000000000000000000000000000001')
        btc_address_1, _, _ = BtcAddress.derive_public_addresses(private_key_bytes)
        assert btc_address_1 == '1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm'

        private_key_bytes = hashlib.sha256(b'cat').digest()
        btc_address_1, _, _ = BtcAddress.derive_public_addresses(private_key_bytes)
        assert btc_address_1 == '162TRPRZvdgLVNksMoMyGJsYBfYtB4Q8tM'

        private_key_bytes = hashlib.sha256(b'hello').digest()
        btc_address_1, _, _ = BtcAddress.derive_public_addresses(private_key_bytes)
        assert btc_address_1 == '1HoSFymoqteYrmmr7s3jDDqmggoxacbk37'

    def test_derive_public_addresses_02(self):
        # Ref: https://github.com/fortesp/bitcoinaddress/blob/master/README.md
        private_key_bytes = bytes.fromhex('03902e4f09664bc177fe4e090dcd9906b432b50f15fb6151984475c1c75c35b6')
        wif_compressed = BtcAddress.convert_private_key_into_wif(private_key_bytes)
        assert wif_compressed == 'KwLdv6T2jmhQbswnYrcL9KZHerTpVyjozp1JNjfP5QuD3GchCwCc'
        btc_address_1, btc_address_3, btc_address_bc1q = BtcAddress.derive_public_addresses(private_key_bytes)
        assert btc_address_1 == '1Bu6YxH64nfvhdDsYNEP8PftoBMqgusdPS'
        assert btc_address_3 == '38dRrGx5YbrnRWuWcJv5i2XHjYUnHE2wvv'
        assert btc_address_bc1q == 'bc1q2jxe5azr6zmhk3258av7ul6cqtu4eu4mps8f4p'

    def test_generate_last_private_key_bytes(self):
        prefix = ''
        for _ in range(64):
            for ch in ['f', 'e', 'd', 'c', 'b', 'a', '9', '8', '7', '6', '5', '4', '3', '2', '1', '0']:
                suffix = ch + '0' * (64 - (len(prefix) + 1))
                private_key_str = prefix + suffix
                private_key_bytes = bytes.fromhex(private_key_str)
                assert len(private_key_str) == 64
                try:
                    BtcAddress.derive_public_addresses(private_key_bytes)
                    break
                except Exception:
                    pass
            else:
                assert False
            prefix += ch
        private_key_str = prefix
        assert private_key_str == 'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140'

        N = ecdsa.SECP256k1.order
        assert f'{N:x}' == 'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141'

        btc_address_1, btc_address_3, btc_address_bc1q = BtcAddress.derive_public_addresses(private_key_bytes)
        assert btc_address_1 == '1JPbzbsAx1HyaDQoLMapWGoqf9pD5uha5m'
        assert btc_address_3 == '38Kw57SDszoUEikRwJNBpypPSdpbAhToeD'
        assert btc_address_bc1q == 'bc1q4h0ycu78h88wzldxc7e79vhw5xsde0n8jk4wl5'
