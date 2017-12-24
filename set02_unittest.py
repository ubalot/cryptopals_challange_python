#!/venv/bin/python

import binascii
import unittest
import random

import os

import util
from utils import converter
from utils.aesencryption import AESEncryption
from utils.attacks import decrypt_in_cbc


class CryptoChallenge(unittest.TestCase):

    def test_Set02_Challenge09(self):
        """
        Implement PKCS#7 padding
        """
        plaintext = b'YELLOW SUBMARINE'  # 16 bytes
        padded = b'YELLOW SUBMARINE\x04\x04\x04\x04'  # to 20 bytes

        plaintext_padded = converter.pkcs7pad(plaintext, 20, b'\x04')

        self.assertEqual(plaintext_padded, padded)

    def test_Set02_Challenge10(self):
        """
        Implement CBC mode
        """
        key = b"YELLOW SUBMARINE"
        iv = bytes([0] * len(key))  # Initialization Vector

        with open('resources/Set02-Challenge10.txt', 'r') as f:
            # Decode text from base64
            cipher_text = converter.decode_base64(f.read())

            # Decrypt a AES encrypted file in CBC mode.
            # plaintext = util.CBC(cipher_text, key, iv)
            plaintext = decrypt_in_cbc(cipher_text, key, iv)

            result = plaintext.decode("utf-8")[:-4]

        with open('resources/Set02-Challenge10-Solution.txt', 'r') as solution:
            expected_result = solution.read()[:-1]

        self.assertEqual(expected_result, result)

    def test_Set02_Challenge11(self):
        """
        An ECB/CBC detection oracle
        """
        tests = 5  # number of tests
        result_list = []
        for _ in range(tests):
            # choose random key
            char = bytes([random.randint(0, 255)])

            # encrypt in ECB or CBC mode
            result = util.encryption_oracle(char * 43)

            # find encryption mode
            result['prediction'] = util.ECB_CBC_oracle(result['ciphertext'])

            result_list.append(result)

        correctly_predicted = True
        for result in result_list:
            if result['mode'] != result['prediction']:
                correctly_predicted = False

        self.assertTrue(correctly_predicted)

    def test_Set02_Challenge12(self):
        """
        Byte-at-a-time ECB decryption (Simple)
        """
        unknown_string = binascii.a2b_base64(
            b'''Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
                aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
                dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
                YnkK'''
        )

        key = util.random_key(16)

        aes_128_ecb = lambda s: util.aes_128_ecb(s, key)

        block_size = util.detect_block_size(aes_128_ecb)

        is_ecb = util.confirm_ECB(aes_128_ecb, block_size)

        res = util.find_every_byte(aes_128_ecb, block_size, unknown_string)

        self.assertTrue(block_size == 16 and is_ecb and res == unknown_string)

    def test_Set2_Challenge13(self):
        """
        ECB cut-and-paste
        """
        cookie = 'foo=bar&baz=qux&zap=zazzle'
        json = util.decode_cookie(cookie)
        expeced_cookie = {
            'foo': 'bar',
            'baz': 'qux',
            'zap': 'zazzle'
        }
        self.assertEqual(json, expeced_cookie)

        profile = util.profile_for('foo@bar.com')
        expeced_profile = 'email=foo@bar.com&uid=10&role=user'
        self.assertEqual(profile, expeced_profile)

        key = AESEncryption().random_key(16)
        ciphertext = AESEncryption(key, 'ECB').encrypt(bytes(profile, encoding='utf-8'))
        # print(ciphertext)
        # decrypted = AESEncryption(key, 'ECB').decrypt(ciphertext)
        # print(decrypted)


        profile = util.profile_for('four@four.com')
        cipher_text= AESEncryption(key, 'ECB').encrypt(bytes(profile, encoding='utf-8'))
        admin_email = ('\x00' * 30) + 'admin'# + ('\x0b' * 29)
        admin_profile = util.profile_for(admin_email)
        admin_cipher_text = AESEncryption(key, 'ECB').encrypt(bytes(admin_profile, encoding='utf-8'))

        res = cipher_text[0:32] + admin_cipher_text[32:64]

        result = AESEncryption(key, 'ECB').decrypt(res)
        # print('result', result)
        self.assertTrue('admin' in result.decode('utf-8'))

    def test_Set2_Challenge14(self):
        """Byte-at-a-time ECB decryption (Harder)"""

        random_bytes = os.urandom(random.randint(0, 10))

        unknown_string = binascii.a2b_base64(
            b'''Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
                aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
                dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
                YnkK'''
        )

        target_bytes = b'my plain text'
        _input = random_bytes + unknown_string + target_bytes

        key = util.random_key(16)

        aes_128_ecb = lambda s: util.aes_128_ecb(s, key)

        block_size = util.detect_block_size(aes_128_ecb)

        result = util.find_every_byte(aes_128_ecb, block_size, _input)

        self.assertTrue(target_bytes in result)

if __name__ == '__main__':
    unittest.main()
