#!/venv/bin/python

import binascii
import os
import unittest
import random
from Crypto.Cipher import AES

import util


class CryptoChallenge(unittest.TestCase):

    def test_Set02_Challenge09(self):
        """
        Implement PKCS#7 padding
        """
        # 16 bytes
        plaintext = 'YELLOW SUBMARINE'
        # to 20 bytes
        padded = 'YELLOW SUBMARINE\x04\x04\x04\x04'

        byte_plaintext = bytes(plaintext, encoding="utf-8")  # to binary
        byte_plaintext_padded = util.pkcs7pad(byte_plaintext, 20, b'\x04')
        plaintext_padded = byte_plaintext_padded.decode(encoding="utf-8")

        self.assertEqual(plaintext_padded, padded)

    def test_Set02_Challenge10(self):
        """
        Implement CBC mode
        """
        key = "YELLOW SUBMARINE"
        bytes_key = bytes(key, encoding="utf-8")
        IV = bytes([0] * len(key))  # Initialization Vector

        with open('resources/Set02-Challenge10.txt', 'r') as f:
            # Decode text from base64
            ciphertext = binascii.a2b_base64(f.read())

            # Decrypt a AES encrypted file in CBC mode.
            plaintext = util.CBC(ciphertext, bytes_key, IV)

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


    def test_Set02_Challenge13(self):
        """
        ECB cut-and-paste
        """
        cookie = 'foo=bar&baz=qux&zap=zazzle'
        json = util.decode_cookie(cookie)
        result = {
            'foo': 'bar',
            'baz': 'qux',
            'zap': 'zazzle'
        }
        # result = [
        #     ('foo', 'bar'),
        #     ('baz', 'qux'),
        #     ('zap', 'zazzle')
        # ]

        self.assertEqual(json, result)

        profile = util.profile_for('foo@bar.com')
        # print(plaintext)
        cookie_result = 'email=foo@bar.com&uid=10&role=user'
        self.assertEqual(profile, cookie_result)

        key = util.random_key(16)
        # ciphertext = util.aes_128_ecb(bytes(profile, encoding='utf-8'), key)

        # attacker = AES.new(key, AES.MODE_ECB)
        # plaintext = attacker.decrypt(ciphertext)

        #  # 10x A to fill the first block, then admin padding for the next block
        # plaintext = util.profile_for('A' * 10 + 'admin' + '\x0b' * 0xb)
        # cipher = AES.new(key, AES.MODE_ECB)
        # ciphertext = cipher.encrypt(util.pkcs7pad(bytes(plaintext)))
        # adminBlock = ciphertext[16:32]  # this is the block that contains admin

        # # now request a regular account and make it an admin account
        # # the mail address correctly aligns the blocks
        # plaintext = profile_for('admin1@me.com')
        # print( 'pre-encrypted data: ', util.decode_cookie(plaintext))
        # ciphertext = cipher.encrypt(util.pkcs7pad(bytes(plaintext)), key)

        # # replace the last block user+padding with admin+padding
        # ciphertext = ciphertext[:-16] + adminBlock
        # plaintext = cipher.decryot(ciphertext)

        # # the object should now contain role: admin
        # print ('manipulated data: ', decode_cookie(str(plaintext)))




    # def test_Set2_Challenge13(self):
    #     """
    #     ECB cut-and-paste
    #     """
    #     cookie = 'foo=bar&baz=qux&zap=zazzle'
    #     json = util.decode_cookie(cookie)
    #     result = {
    #         'foo': 'bar',
    #         'baz': 'qux',
    #         'zap': 'zazzle'
    #     }
    #     self.assertEqual(json, result)
    #     # self.assertEqual(util.profile_for(json), cookie)



if __name__ == '__main__':
    unittest.main()
