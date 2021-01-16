class CTR:
    def __init__(self, cipher, nonce):
        # Nonce will be half of the block_size of the cipher
        # Counter will start at 0
        self.cipher = cipher
        self.nonce = nonce

    def _xor(self, data_1, data_2):
        return [a ^ b for a, b in zip(data_1, data_2)]

    def encrypt(self, data_block, counter):
        # len(nonce + counter) should be equal to the block size: 16 bytes (128 bits) for AES
        # len(nonce) == 10 bytes by definition
        # len(counter) == 6 bytes by definition
        counter_bytes = counter.to_bytes(6, byteorder="big")

        # Combine nonce and counter to make IV
        IV = self.nonce + counter_bytes
        ciphertext = bytes(self._xor(self.cipher.encrypt(IV), data_block))
        return ciphertext

    def decrypt(self, cipher_block, counter):
        # Decryption is the same as encryption, but using cipher_block instead
        return self.encrypt(cipher_block, counter)