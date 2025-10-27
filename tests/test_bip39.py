from lib.bip39 import Bip39


class TestBip39:
    # Ref: https://github.com/trezor/python-mnemonic/blob/master/vectors.json
    PASSPHRASE = 'TREZOR'

    def test_get_wordlist(self):
        wordlist = Bip39.get_wordlist()
        assert len(wordlist) == 2048

    def test_generate_random_mnemonic(self):
        mnemonic = Bip39.generate_random_mnemonic(128)
        words = mnemonic.strip().split()
        assert (len(words) == 12)

        mnemonic = Bip39.generate_random_mnemonic(256)
        words = mnemonic.strip().split()
        assert (len(words) == 24)

    def test_mnemonic_to_entropy(self):
        mnemonic = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
        entropy = Bip39.mnemonic_to_entropy(mnemonic)
        assert entropy.hex() == '00000000000000000000000000000000'

        mnemonic = 'void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold'
        entropy = Bip39.mnemonic_to_entropy(mnemonic)
        assert entropy.hex() == 'f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f'

    def test_entropy_to_mnemonic(self):
        entropy = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        mnemonic = Bip39.entropy_to_mnemonic(entropy)
        assert mnemonic == 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'

        entropy = b'\xf5\x85\xc1\x1a\xec\x52\x0d\xb5\x7d\xd3\x53\xc6\x95\x54\xb2\x1a\x89\xb2\x0f\xb0\x65\x09\x66\xfa\x0a\x9d\x6f\x74\xfd\x98\x9d\x8f'
        mnemonic = Bip39.entropy_to_mnemonic(entropy)
        assert mnemonic == 'void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold'

    def test_mnemonic_and_passphrase_to_seed(self):
        mnemonic = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
        seed = Bip39.mnemonic_and_passphrase_to_seed(mnemonic, TestBip39.PASSPHRASE)
        assert seed.hex() == 'c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04'

        mnemonic = 'void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold'
        seed = Bip39.mnemonic_and_passphrase_to_seed(mnemonic, TestBip39.PASSPHRASE)
        assert seed.hex() == '01f5bced59dec48e362f2c45b5de68b9fd6c92c6634f44d6d40aab69056506f0e35524a518034ddc1192e1dacd32c1ed3eaa3c3b131c88ed8e7e54c49a5d0998'
