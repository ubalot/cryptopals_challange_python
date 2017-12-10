#!/venv/bin/python

import binascii
import os
import unittest
from Crypto.Cipher import AES

import util

class CryptoChallenge(unittest.TestCase):


    def test_Set01_Challenge01(self):
        """
        Convert hex to base64
        """
        # Given values
        hex_string = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
        result = 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'

        binary = binascii.a2b_hex(hex_string)  # hex ascii to binary
        ascii_string = binascii.b2a_base64(binary)  # binary to base64 ascii
        base64_string = ascii_string.decode("utf-8")[:-1]  # get rid of new line

        self.assertEqual(base64_string, result)


    def test_Set01_Challenge02(self):
        """
        Fixed XOR
        """
        # Given values
        hex_string = '1c0111001f010100061a024b53535009181c'
        hex_xor_buffer = '686974207468652062756c6c277320657965'
        result = '746865206b696420646f6e277420706c6179'

        # Convert hex ascii to binary
        binary_buffer_1 = binascii.a2b_hex(hex_string)
        binary_buffer_2 = binascii.a2b_hex(hex_xor_buffer)

        # Xor
        xored_buffer = util.fixed_xor(binary_buffer_1, binary_buffer_2)

        # Convert binary to hex
        xored_hex = binascii.b2a_hex(xored_buffer)

        # Decode hex to utf-8
        xored = xored_hex.decode('utf-8')

        self.assertEqual(xored, result)


    def test_Set01_Challenge03(self):
        """
        Single-byte XOR cipher
        """
        # Given values
        hex_string = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'

        # Decoding hex to binary
        binary = binascii.a2b_hex(hex_string)

        # Brute-force hex_string and find the char it was xored against.
        result = util.find_xor_singlechar_key(binary)

        # Results
        plaintext = result['plaintext']
        key = result['key']

        # Probable result (from previous tests).
        expected_plaintext = "Cooking MC's like a pound of bacon"
        expected_key = 'X'

        self.assertTrue(expected_plaintext == plaintext and expected_key == key)


    def test_Set01_Challenge04(self):
        """
        Detect single-character XOR
        """
        with open('resources/Set01-Challenge04.txt', 'r') as ciphertext_file:

            winner = {
                'score': 0,
                'plaintext': "",
                'key': ''
            }

            for ciphertext in ciphertext_file:
                ciphertext = ciphertext.replace('\n', '')

                # Decode from hex
                decoded_binary = binascii.a2b_hex(ciphertext)

                result = util.find_xor_singlechar_key(decoded_binary)
                if result['score'] > winner['score']:
                    winner['score'] = result['score']
                    winner['plaintext'] = result['plaintext']
                    winner['key'] = result['key']

            plaintext = winner['plaintext'][:-1]  # get rid of '\n'
            key = winner['key']

        expected_plaintext = 'Now that the party is jumping'
        expected_key = '5'
        self.assertTrue(expected_plaintext == plaintext and expected_key == key)


    def test_Set01_Challenge05(self):
        """
        Implement repeating-key XOR
        """
        # Given values
        input_string = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
        key = "ICE"
        expected_output = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"

        # Convert strings to binary form
        binary_input = bytes(input_string, encoding='utf-8')
        binary_key = bytes(key, encoding='utf-8')

        # xor input with key
        result = util.repeating_xor(binary_input, binary_key)

        # Encode to hex
        result = binascii.b2a_hex(result).decode()

        self.assertEqual(result, expected_output)


    def test_Set01_Challenge06(self):
        """
        Break repeating-key XOR
        """
        with open('resources/Set01-Challenge06.txt', 'r') as ciphertext_file:
            content = ciphertext_file.read()

            # Decode from base64.
            ciphertext = binascii.a2b_base64(content)

            result = util.break_repeating_key_xor(ciphertext)

            key = result['key'].decode("utf-8")
            plaintext = result['plaintext'].decode("utf-8")

            expected_key = "Terminator X: Bring the noise"
        
        with open('resources/Set01-Challenge06-Solution.txt', 'r') as solution:
            expected_plaintext = solution.read()[:-1]  # get rid of '\n'

        self.assertTrue(expected_plaintext == plaintext and expected_key == key)


    def test_Set01_Challenge07(self):
        """
        AES in ECB mode
        """
        # 16 char length and 16 bytes length
        key = 'YELLOW SUBMARINE'
        byte_key = bytes(key, encoding="utf-8")  # binary form
        
        with open('resources/Set01-Challenge07.txt', 'r') as f:
            content = f.read()
            # Decode base64
            ciphertext = binascii.a2b_base64(content)

            # Create object AES in MODE_ECB
            cipher = AES.new(byte_key, AES.MODE_ECB)

            # Decrypt from AES
            plaintext = cipher.decrypt(ciphertext).decode("utf-8")[:-4]
        
        with open('resources/Set01-Challenge07-Solution.txt', 'r') as solution:
            expected_result = solution.read()[:-1]
        
        self.assertEqual(expected_result, plaintext)


    def test_Set01_Challenge08(self):
        """
        Detect AES in ECB mode
        """
        result = None
        with open('resources/Set01-Challenge08.txt', 'r') as f:
            for line in f:
                if util.is_ECB_encrypted(line, 16):
                    result = line

        with open('resources/Set01-Challenge08-Solution.txt', 'r') as solution:
            expected_result = solution.read()[:-1]
        
        self.assertEqual(expected_result, result)


if __name__ == '__main__':
    unittest.main()
