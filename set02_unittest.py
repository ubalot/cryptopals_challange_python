#!/venv/bin/python

import binascii
import unittest
import random

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


    # def test_Set02_Challenge13(self):
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
    #     # result = [
    #     #     ('foo', 'bar'),
    #     #     ('baz', 'qux'),
    #     #     ('zap', 'zazzle')
    #     # ]
    #
    #     self.assertEqual(json, result)
    #
    #     profile = util.profile_for('foo@bar.com')
    #     # print(plaintext)
    #     cookie_result = 'email=foo@bar.com&uid=10&role=user'
    #     self.assertEqual(profile, cookie_result)
    #
    #     key = util.random_key(16)
    #     # ciphertext = util.aes_128_ecb(bytes(profile, encoding='utf-8'), key)
    #
    #     # attacker = AES.new(key, AES.MODE_ECB)
    #     # plaintext = attacker.decrypt(ciphertext)
    #
    #     #  # 10x A to fill the first block, then admin padding for the next block
    #     # plaintext = util.profile_for('A' * 10 + 'admin' + '\x0b' * 0xb)
    #     # cipher = AES.new(key, AES.MODE_ECB)
    #     # ciphertext = cipher.encrypt(util.pkcs7pad(bytes(plaintext)))
    #     # adminBlock = ciphertext[16:32]  # this is the block that contains admin
    #
    #     # # now request a regular account and make it an admin account
    #     # # the mail address correctly aligns the blocks
    #     # plaintext = profile_for('admin1@me.com')
    #     # print( 'pre-encrypted data: ', util.decode_cookie(plaintext))
    #     # ciphertext = cipher.encrypt(util.pkcs7pad(bytes(plaintext)), key)
    #
    #     # # replace the last block user+padding with admin+padding
    #     # ciphertext = ciphertext[:-16] + adminBlock
    #     # plaintext = cipher.decryot(ciphertext)
    #
    #     # # the object should now contain role: admin
    #     # print ('manipulated data: ', decode_cookie(str(plaintext)))




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

        # key = util.random_key(16)
        key = AESEncryption().random_key(16)
        # ciphertext = util.aes_128_ecb(bytes(profile, encoding='utf-8'), key)
        ciphertext = util.aes_128_ecb(bytes(profile, encoding='utf-8'), key)
        print(ciphertext)
        decrypted = util.CBC(ciphertext, key)
        print(decrypted)

        # attacker = AES.new(key, AES.MODE_ECB)
        # bytes_plaintext = attacker.decrypt(ciphertext)
        # plaintext = bytes_plaintext.decode('utf-8').replace('\x04', '')
        # self.assertEqual(profile, plaintext)

        def ecb_cut_and_paste(encryption_oracle):
            """By cutting and pasting pieces of ciphertexts, forces a ciphertext of an admin user"""

            # The first plaintext that will be encrypted is:
            # block 1:           block 2 (pkcs7 padded):                             and (omitting the padding):
            # email=xxxxxxxxxx   admin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b   &uid=10&role=user
            prefix_len = AES.block_size - len("email=")
            suffix_len = AES.block_size - len("admin")
            email1 = 'x' * prefix_len + "admin" + (chr(suffix_len) * suffix_len)
            encrypted1 = encryption_oracle.encrypt(email1)

            # The second plaintext that will be encrypted is:
            # block 1:           block 2:           block 3
            # email=master@me.   com&uid=10&role=   user\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c
            email2 = "master@me.com"
            encrypted2 = encryption_oracle.encrypt(email2)

            # The forced ciphertext will cut and paste the previous ciphertexts to be decrypted as:
            # block 1:           block 2:           block 3:
            # email=master@me.   com&uid=10&role=   admin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b
            forced = encrypted2[:32] + encrypted1[16:32]

            return forced


if __name__ == '__main__':
    unittest.main()
