import itertools

import constants


class BinaryDataOperators(object):

    @staticmethod
    def xor(byte1, byte2):
        return bytes([byte1 ^ byte2])

    def fixed_xor(self, buffer1, buffer2):
        """'buffer1' and 'buffer2' must be of the same length.
        Return the a bytes string resulted from buffer1 xored buffer2.

        :param buffer1: bytes
        :param buffer2: bytes
        :return: bytes
        """
        if type(buffer1) is not bytes or type(buffer2) is not bytes:
            raise ValueError("Wrong type input: use bytes string.")

        if len(buffer1) != len(buffer2):
            raise ValueError("Undefined for sequences of unequal length")

        return b''.join([self.xor(b1, b2) for b1, b2 in zip(buffer1, buffer2)])

    def xor_singlechar(self, buffer, key):
        """Input string must be in binary form.
        Return the buffer xored against a single char repeated for buffer length.

        :param buffer: bytes
        :param key: bytes
        :return: bytes
        """
        key_buffer = b''.ljust(len(buffer), bytes([key]))
        return self.fixed_xor(buffer, key_buffer)

    def repeating_xor(self, buffer, key):
        """Input_bytes and key_pad must be bytes string.
        Return input_bytes xored with key_pad, key_pad is repeated for all input_bytes
        length.

        :param buffer: bytes
        :param key: bytes
        :return: bytes
        """
        padded_key = itertools.cycle(key)  # yield key forever
        return b''.join([self.xor(b_1, b_2) for b_1, b_2 in zip(buffer, padded_key)])

    @staticmethod
    def hamming_distance(string1, string2):
        """
        string1 and string2 must be in bytes string.

        Return number of '1' in xor(string1, string2), it tell's how many bit
        are differents.
        """
        if len(string1) != len(string2):
            raise ValueError("Undefined for sequences of unequal length")

        return sum([bin(b1 ^ b2).count('1') for b1, b2 in zip(string1, string2)])

    def normalized_hamming_distance(self, *strings):
        """
        Get arbitrary number of input, but it's the same as:
            return hamming_distance(string1, string2) / len(string1)
        """
        blocksize = len(strings[0])
        couples = itertools.combinations(strings, 2)
        return sum([(self.hamming_distance(s1, s2) / blocksize) for s1, s2 in couples])
