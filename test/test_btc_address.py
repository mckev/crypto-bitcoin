import hashlib
import unittest

from classes.btc_address import BtcAddress


class TestBtcAddress(unittest.TestCase):

    def test_convert_btc_private_key_into_wif(self):
        # Ref: https://en.bitcoin.it/wiki/Wallet_import_format
        btc_private_key = bytes.fromhex('0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D')
        btc_private_key_in_wif = BtcAddress.convert_btc_private_key_into_wif(btc_private_key)
        self.assertEqual(btc_private_key_in_wif, '5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ')

    def test_convert_btc_wif_into_btc_private_key(self):
        btc_private_key = BtcAddress.convert_btc_wif_into_private_key(
            '5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ')
        self.assertEqual(btc_private_key,
                         bytes.fromhex('0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D'))

    def test_compute_btc_address(self):
        # Ref: https://www.palkeo.com/en/blog/stealing-bitcoin.html
        btc_private_key_01 = bytes.fromhex('0000000000000000000000000000000000000000000000000000000000000001')
        btc_address_01 = BtcAddress.compute_btc_address(btc_private_key_01)
        self.assertEqual(btc_address_01, '1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm')

        btc_private_key_02 = hashlib.sha256(b'cat').digest()
        btc_address_02 = BtcAddress.compute_btc_address(btc_private_key_02)
        self.assertEqual(btc_address_02, '162TRPRZvdgLVNksMoMyGJsYBfYtB4Q8tM')

        btc_private_key_03 = hashlib.sha256(b'hello').digest()
        btc_address_03 = BtcAddress.compute_btc_address(btc_private_key_03)
        self.assertEqual(btc_address_03, '1HoSFymoqteYrmmr7s3jDDqmggoxacbk37')

    def test_btc_key_pair(self):
        # Ref: https://bitcoinpaperwallet.com/bitcoinpaperwallet/generate-wallet.html
        btc_private_key_in_wif = '5Jt6kGhPb6pHCLqsLDXttV42ubs59kPwuZWt75zM2aSVwWeDoCA'
        btc_private_key = BtcAddress.convert_btc_wif_into_private_key(btc_private_key_in_wif)
        btc_address = BtcAddress.compute_btc_address(btc_private_key)
        self.assertEqual(btc_address, '1P7va58iqk5DWymibs2KEuocg1qUZzjhWF')
