"""
Generate BTC addresses which has predefined prefix.
For example my BTC address: 1KeVN9yzZVqGRhB7MYWb2AdUQdjrDBjNQM
"""

import secrets

from btc import BTC

while True:
    btc_private_key = secrets.token_bytes(nbytes=32)
    btc_address = BTC.compute_btc_address(btc_private_key)
    if btc_address.lower().startswith('1kev'):
        btc_private_key_in_wif = BTC.convert_btc_private_key_into_wif(btc_private_key)
        print('{} - {}'.format(btc_address, btc_private_key_in_wif))
