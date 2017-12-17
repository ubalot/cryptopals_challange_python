import itertools

import constants
from utils.binary_data_operators import BinaryDataOperators


class Attacks(object):
    operators = BinaryDataOperators()

    @staticmethod
    def explode(string, block_size):
        return [string[i:i + block_size] for i in range(0, len(string), block_size)]

    def probable_keysize(self, ciphertext):
        keysizes = {}

        for size in range(2, 41):

            # Take just the four blocks for a quick check.
            blocks = self.explode(ciphertext, size)[:4]

            # Check same length of blocks before calling normalized_hamming_distance
            i, j, k, l = (blocks[i] for i in range(4))
            if len(i) == len(j) == len(k) == len(l):
                keysizes.setdefault(
                    self.operators.normalized_hamming_distance(i, j, k, l),
                    size
                )

        # Return the keysize associated to the minimum normalized hamming distance.
        return keysizes.get(min(keysizes.keys()))

    def break_repeating_key_xor(self, ciphertext):
        # Get most probable key length (keysize).
        keysize = self.probable_keysize(ciphertext)

        # Break ciphertext in blocks of length keysize.
        blocks = self.explode(ciphertext, keysize)

        # Transpose blocks.
        # *blocks: argument will be unpacked. In other words, the elements of the
        # list are singularized.
        transposed_blocks = list(itertools.zip_longest(*blocks, fillvalue=0))

        # Find the key of each transposed block and put it in a list
        keys = [self.find_xor_singlechar_key(bytes(block))['key'] for block
                in transposed_blocks]

        key = bytes(''.join(keys), encoding="utf-8")  # eg: "c" -> b"c"

        # Decrypt plaintext with the key
        plaintext = self.operators.repeating_xor(ciphertext, key)

        return {
            'key': key,
            'plaintext': plaintext
        }

    def find_xor_singlechar_key(self, ciphertext):
        """ Ciphertext must be in binary form.

        :param ciphertext: bytes
        :return: dict
        """
        CHAR_FREQUENCY = constants.CHAR_FREQUENCY

        # Store temporary best score.
        result = {
            "plaintext": "",
            "score": 0,
            "key": ''
        }

        # Test every number from 0 to 255 as possible key.
        for key in range(256):
            plaintext = self.operators.xor_singlechar(ciphertext, key)

            score = 0

            for byte in plaintext:
                # Add the frequency of the character to the score
                char = bytes([byte]).decode('latin-1').lower()
                if char in CHAR_FREQUENCY.keys():
                    score += CHAR_FREQUENCY[char]

            if score > result['score']:
                result['score'] = score
                result['plaintext'] = plaintext.decode('latin-1')
                result['key'] = chr(key)

        return result