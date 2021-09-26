"""
Generate BTC addresses which have predefined prefix.
"""

import secrets

from classes.btc_address import BtcAddress

while True:
    btc_private_key = secrets.token_bytes(nbytes=32)
    btc_address = BtcAddress.compute_btc_address(btc_private_key)
    if btc_address.lower().startswith('1kev'):
        btc_private_key_in_wif = BtcAddress.convert_btc_private_key_into_wif(btc_private_key)
        print('{} - {}'.format(btc_address, btc_private_key_in_wif))
