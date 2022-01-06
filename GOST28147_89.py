class GOST28147_89:
    def __init__(self):
        self._mod = 1 << 32
        # Central Bank of Russian Federation uses this S-boxes
        self._s_box = (
                                (4, 10, 9, 2, 13, 8, 0, 14, 6, 11, 1, 12, 7, 15, 5, 3),
                                (14, 11, 4, 12, 6, 13, 15, 10, 2, 3, 8, 1, 0, 7, 5, 9),
                                (5, 8, 1, 13, 10, 3, 4, 2, 14, 15, 12, 7, 6, 0, 9, 11),
                                (7, 13, 10, 1, 0, 8, 9, 15, 14, 4, 6, 12, 11, 2, 5, 3),
                                (6, 12, 7, 1, 5, 15, 13, 8, 4, 10, 9, 14, 0, 3, 11, 2),
                                (4, 11, 10, 0, 7, 2, 1, 13, 3, 6, 8, 5, 9, 12, 15, 14),
                                (13, 11, 4, 1, 3, 15, 5, 9, 0, 10, 14, 7, 6, 8, 2, 12),
                                (1, 15, 13, 0, 5, 7, 10, 4, 9, 2, 3, 14, 6, 11, 8, 12),
        )


    def get_message_blocks(self):
        pass


    def get_key(self):
        return self._key


    # Nonlinear function
    def f(self, right, k_i):
        right = (right + k_i) & 0xFFFFFFFF # % self._mod
        # print(f'Temp: {hex(right)}')
        right = self.s(right)
        output = ((right << 11) & 0xFFFFFFFF) | (right >> 21)
        # print(f'F_output: {hex(output)}')
        return output


    # Substitution
    def s(self, right):
        result = 0
        for i in range(8):
            result |= ((self._s_box[i][(right >> (4 * i)) & 0xf]) << (4 * i))
        return result


    def encryption_round(self, input_left, input_right, round_key):
        output_left = input_right
        output_right = input_left ^ self.f(input_right, round_key) # calculate right part
        return output_left, output_right


    def decryption_round(self, input_left, input_right, round_key):
        output_right = input_left
        output_left = input_right ^ self.f(input_left, round_key)
        return output_left, output_right


    def encrypt(self, block, key):
        left, right = block >> 32, block & 0xFFFFFFFF # left-right partition
        for i in range(32):
            k_i = key[i % 8] if i < 24 else key[7 - (i % 8)] # K_0, ..., K_7 for i < 24 and K_7, ..., K_0 for i >= 24
            left, right = self.encryption_round(left, right, k_i)
        return (left << 32) | right # make 64 bit block


    def decrypt(self, block, key):
        left, right = block >> 32, block & 0xFFFFFFFF # left-right partition
        for i in range(32):
            k_i = key[i] if i < 8 else key[7 - (i % 8)] # K_0, ..., K_7 for i < 8 and K_7, ..., K_0 for i >= 8
            left, right = self.decryption_round(left, right, k_i)
        return (left << 32) | right # make 64 bit block


if __name__ == '__main__':
    import time
    cipher = GOST28147_89()
    data = 0xFE12847EFE12847E # 64 bit block
    key = [0xFFFFFFFF, 0x12345678, 0x00120477, 0x77AE441F, 0x81C63123, 0x99DEEEEE, 0x09502978, 0x68FA3105]
    g = 128 * 1024 #one MB
    start = time.time()
    for i in range(g):
        ct = cipher.encrypt(data, key)
    print('=' * 30)
    decrypted = cipher.decrypt(ct, key)
    print((time.time() - start) / g)

    print(f'Text: {hex(data)}\nCiphertext: {hex(ct)}\nDecrypted text: {hex(decrypted)}\n{data == decrypted}')
