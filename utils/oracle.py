import os
import random

from utils import converter
from utils.aesencryption import AESEncryption


def get_block(buffer, block_size, index):
    return buffer[block_size * index: block_size * (index + 1)]


def is_ECB_encrypted(ciphertext, block_size):
    block_count = int(len(ciphertext) / block_size)

    # Test each block against every block that follow it:
    # if they are the same, ciphertext is ECB encoded.
    for i in range(block_count - 1):
        focus_block = get_block(ciphertext, block_size, i)
        for j in range(i + 1, block_count):
            if focus_block == get_block(ciphertext, block_size, j):
                return True
    return False


def encryption_oracle(plaintext):
    """ Encrypt plaintext with a random key. """

    key = os.urandom(16)

    # Add prefix and suffix to plaintext.
    prefix = AESEncryption().random_key(random.randrange(5, 11))
    suffix = AESEncryption().random_key(random.randrange(5, 11))
    plaintext = prefix + plaintext + suffix

    # Then pad it.
    plaintext = converter.pkcs7pad(plaintext, 16, b'\x04')

    # Choose a random mode
    mode = random.choice(['ECB', 'CBC'])

    if mode == 'ECB':
        """ ECB encryption """
        # cipher = AES.new(key, AES.MODE_ECB)
        # ciphertext = cipher.encrypt(plaintext)
        cipher = AESEncryption(key, 'ECB')
        ciphertext = cipher.encrypt(plaintext)
    else:
        """ CBC encryption """
        IV = os.urandom(16)
        ciphertext = AESEncryption(key, 'CBC').decrypt(plaintext, IV)

    result = {
        'ciphertext': ciphertext,
        'mode': mode
    }
    return result
