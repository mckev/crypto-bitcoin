import hashlib
import os
import secrets
import unicodedata


class Bip39:

    @staticmethod
    def get_wordlist():
        # https://raw.githubusercontent.com/bitcoin/bips/refs/heads/master/bip-0039/english.txt
        wordlist = []
        dir = os.path.dirname(__file__)
        with open(os.path.join(dir, 'bip39_wordlist.txt'), 'rt') as f:
            for line in f:
                line = line.rstrip('\r\n')
                wordlist.append(line)
        assert len(wordlist) == 2048
        return wordlist

    @staticmethod
    def sha256(b: bytes) -> bytes:
        return hashlib.sha256(b).digest()

    @staticmethod
    def bits_to_bytes(bits: str) -> bytes:
        if len(bits) % 8 != 0:
            raise ValueError(f'Bits length {len(bits)} must be multiple of 8')
        return bytes(int(bits[i: i+8], 2) for i in range(0, len(bits), 8))

    @staticmethod
    def bytes_to_bits(bytes: bytes) -> str:
        return ''.join(f'{byte:08b}' for byte in bytes)

    @staticmethod
    def generate_random_mnemonic(entropy_len: int = 256) -> str:
        if entropy_len not in [128, 160, 192, 224, 256]:
            raise ValueError(f'Entropy length {entropy_len} must be one of 128, 160, 192, 224 or 256')
        entropy_bytes = secrets.token_bytes(entropy_len // 8)
        return Bip39.entropy_to_mnemonic(entropy_bytes)

    @staticmethod
    def mnemonic_to_entropy(mnemonic: str) -> bytes:
        # Ref: https://en.bitcoin.it/wiki/BIP_0039
        words = mnemonic.strip().split()
        if len(words) not in [12, 15, 18, 21, 24]:
            raise ValueError('Mnemonic must have 12, 15, 18, 21 or 24 words')

        # Convert words into indexes
        indexes = []
        wordlist = Bip39.get_wordlist()
        for word in words:
            try:
                index = wordlist.index(word)
            except ValueError:
                raise ValueError(f'Word {word} is not in BIP39 English wordlist')
            indexes.append(index)

        # Convert indexes into bits
        bits = ''.join(f'{index:011b}' for index in indexes)

        # Calculate entropy and checksum
        # |  Entropy Len | Checksum Len | Total Len | Mnemonic Words |
        # +--------------+--------------+-----------+----------------+
        # |     128      |      4       |    132    |       12       |
        # |     160      |      5       |    165    |       15       |
        # |     192      |      6       |    198    |       18       |
        # |     224      |      7       |    231    |       21       |
        # |     256      |      8       |    264    |       24       |
        checksum_len = len(bits) // 33
        entropy_len = len(bits) - checksum_len
        if entropy_len % 8 != 0:
            raise ValueError(f'Entropy length {entropy_len} must be multiple of 8')
        entropy_bits = bits[:entropy_len]
        entropy_bytes = Bip39.bits_to_bytes(entropy_bits)

        # Validate checksum
        hash_bits = Bip39.bytes_to_bits(Bip39.sha256(entropy_bytes))
        checksum_bits = hash_bits[:checksum_len]
        expected_checksum_bits = bits[entropy_len:]
        if checksum_bits != expected_checksum_bits:
            raise ValueError('Invalid checksum for mnemonics')

        return entropy_bytes

    @staticmethod
    def entropy_to_mnemonic(entropy_bytes: bytes) -> str:
        entropy_len = len(entropy_bytes)
        if entropy_len not in [16, 20, 24, 28, 32]:
            raise ValueError(f'Entropy length {entropy_len} must be 16, 20, 24, 28 or 32 bytes')

        # Entropy
        entropy_bits = Bip39.bytes_to_bits(entropy_bytes)

        # Checksum
        hash_bits = Bip39.bytes_to_bits(Bip39.sha256(entropy_bytes))
        checksum_len = entropy_len * 8 // 32
        checksum_bits = hash_bits[:checksum_len]

        bits = entropy_bits + checksum_bits

        # Split into 11-bit words
        words = []
        wordlist = Bip39.get_wordlist()
        for i in range(0, len(bits), 11):
            index = int(bits[i: i+11], 2)
            words.append(wordlist[index])
        return ' '.join(words)

    @staticmethod
    def mnemonic_and_passphrase_to_seed(mnemonic: str, passphrase: str = '') -> bytes:
        """
        Derive seed from mnemonic using PBKDF2-HMAC-SHA512 as per BIP39.
        mnemonic and passphrase are normalized with NFKD as per spec.
        Returns 64-byte seed.
        """
        # Normalized
        mnemonic_normalized = unicodedata.normalize('NFKD', mnemonic)
        mnemonic_bytes = mnemonic_normalized.encode('utf-8')
        passphrase_normalized = unicodedata.normalize('NFKD', passphrase)
        salt_bytes = ('mnemonic' + passphrase_normalized).encode('utf-8')

        # PBKDF2-HMAC-SHA512, 2048 iterations, 64 bytes
        seed = hashlib.pbkdf2_hmac('sha512', mnemonic_bytes, salt_bytes, 2048, dklen=64)
        assert (len(seed) == 64)
        return seed
