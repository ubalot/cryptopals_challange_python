"""
Library of functions for CryptoChallange.
"""
import binascii
import itertools
import os
import random
import re
import sys

from Crypto.Cipher import AES

import constants


def xor(byte1, byte2):
    return bytes([byte1 ^ byte2])

def fixed_xor(buffer1, buffer2):
    """
    Byte strings of the same length as input.
    Return the Byte string resulted by buffer1 xored buffer2.
    """
    if len(buffer1) != len(buffer2):
        raise ValueError("Undefined for sequences of unequal length")

    return b''.join([xor(b1, b2) for b1, b2 in zip(buffer1, buffer2)])

def xor_singlechar(buffer, key):
    """
    Input string must be in binary form.
    Return the buffer xored against a single char repeated for buffer length.
    """
    key_buffer = b''.ljust(len(buffer), bytes([key]))
    return fixed_xor(buffer, key_buffer)


def find_xor_singlechar_key(ciphertext):
    """ Ciphertext must be in binary form. Return a dictionary. """
    CHAR_FREQUENCY = constants.CHAR_FREQUENCY

    # Store temporary best score.
    result = {
        "plaintext": "",
        "score": 0,
        "key": ''
    }

    # Test every number from 0 to 255 as possible key.
    for key in range(256):
        plaintext = xor_singlechar(ciphertext, key)

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

def repeating_xor(buffer, key):
    """
    input_bytes and key_pad must be bytes string.

    Return input_bytes xored with key_pad, key_pad is repeated for all input_bytes
    length.
    """
    padded_key = itertools.cycle(key)  # yield key forever
    return b''.join([xor(b_1, b_2) for b_1, b_2 in zip(buffer, padded_key)])


def hamming_distance(string1, string2):
    """
    string1 and string2 must be in bytes string.

    Return number of '1' in xor(string1, string2), it tell's how many bit
    are differents.
    """
    if len(string1) != len(string2):
        raise ValueError("Undefined for sequences of unequal length")

    return sum([bin(b1 ^ b2).count('1') for b1, b2 in zip(string1, string2)])


def normalized_hamming_distance(*strings):
    """
    Get arbitrary number of input, but it's the same as:
        return hamming_distance(string1, string2) / len(string1)
    """
    blocksize = len(strings[0])
    couples = itertools.combinations(strings, 2)
    return sum([(hamming_distance(s1, s2) / blocksize) for s1, s2 in couples])


def explode(string, block_size):
    return [string[i:i+block_size] for i in range(0, len(string), block_size)]


def get_block(buffer, block_size, index):
    return buffer[block_size * index : block_size * (index + 1)]


def probable_keysize(ciphertext):
    keysizes = {}

    for size in range(2, 41):

        # Take just the four blocks for a quick check.
        blocks = explode(ciphertext, size)[:4]

        # Check same length of blocks before calling normalized_hamming_distance
        i, j, k, l = (blocks[i] for i in range(4))
        if len(i) == len(j) == len(k) == len(l):
            keysizes.setdefault(
                normalized_hamming_distance(i, j, k, l),
                size
            )

    # Return the keysize associated to the minimum normalized hamming distance.
    return keysizes.get(min(keysizes.keys()))


def break_repeating_key_xor(ciphertext):
    # Get most probable key length (keysize).
    keysize = probable_keysize(ciphertext)

    # Break ciphertext in blocks of length keysize.
    blocks = explode(ciphertext, keysize)

    # Transpose blocks.
    # *blocks: argument will be unpacked. In other words, the elements of the
    # list are singularized.
    transposed_blocks = list(itertools.zip_longest(*blocks, fillvalue=0))

    # Find the key of each transposed block and put it in a list
    keys = [find_xor_singlechar_key(bytes(block))['key'] for block
                   in transposed_blocks]

    key = bytes(''.join(keys), encoding="utf-8")  # eg: "c" -> b"c"

    # Decrypt plaintext with the key
    plaintext = repeating_xor(ciphertext, key)

    return {
        'key': key,
        'plaintext': plaintext
    }


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


def pkcs7pad(ciphertext, blocksize, value=b'\x04'):
    """
    ciphertext: bytes string, blocksize: int, value: bytes char
    Return ciphertext padded with value until it reach blocksize length.
    """
    length = len(ciphertext)
    pad = blocksize - (length % blocksize)
    return b''.join((ciphertext, value * pad))


def CBC(ciphertext, key=None, IV=None):
    """ Arguments must be bytes strings. """
    key = bytes([0] * 16) if not key else key
    IV =  bytes([0] * len(key)) if not IV else IV

    block_size = len(key)
    block_count = int(len(ciphertext) / block_size)

    cipher = AES.new(key, AES.MODE_ECB)

    plaintext = b''
    prev_block = IV

    for i in range(block_count):
        block = get_block(ciphertext, block_size, i)
        xored = fixed_xor(cipher.decrypt(block), prev_block)
        plaintext += xored
        prev_block = block

    return plaintext


def random_key(length):
    """ Return a random generated bytes string of length 'length'. """
    return os.urandom(length)


def encryption_oracle(plaintext):
    """ Encrypt plaintext with a random key. """

    key = os.urandom(16)

    # Add prefix and suffix to plaintext.
    prefix = random_key(random.randrange(5, 11))
    suffix = random_key(random.randrange(5, 11))
    plaintext = prefix + plaintext + suffix

    # Then pad it.
    plaintext = pkcs7pad(plaintext, 16, b'\x04')

    # Choose a random mode
    mode = random.choice(['ECB', 'CBC'])

    ciphertext = b''
    if mode == 'ECB':
        """ ECB encryption """
        cipher = AES.new(key, AES.MODE_ECB)
        ciphertext = cipher.encrypt(plaintext)
    else:
        """ CBC encryption """
        IV = os.urandom(16)
        ciphertext = CBC(plaintext, key, IV)

    result = {
        'ciphertext': ciphertext,
        'mode': mode
    }
    return result


def ECB_CBC_oracle(ciphertext):
    if is_ECB_encrypted(ciphertext, 16):
        return 'ECB'
    else:
        return 'CBC'


def ECB_encryption_oracle(plaintext, key):
    """ Encrypt plaintext with a random key. """

    decoded_key = binascii.b2a_base64(key)
    decoded_key = base64.b64decode(key)
    plaintext += decoded_key   # Append key to plaintext
    plaintext = pkcs7pad(plaintext, 16, b'\x04')  # add pad

    # ECB encryption
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(plaintext)

    return ciphertext


def aes_128_ecb(string, key=None):
    if not key or len(key) != 16:
        print('insert a key...', file=sys.stderr)
        key = random_key(16)
    cipher = AES.new(key)
    padded = pkcs7pad(string, 16)
    return cipher.encrypt(padded)


def confirm_ECB(encryption, blocksize):
    """ Check if encryption oracle is a ECB encryption function. """
    plaintext = random_key(blocksize) * 2
    ciphertext = encryption(plaintext)
    if ciphertext[0:blocksize] != ciphertext[blocksize:2*blocksize]:
        return False
    return True


def detect_block_size(encryption_function):
    """ Given a block mode encryption function, determine the block size. """
    return len(encryption_function(b'A'))


def find_next_byte(encryption, block_size, unknown_string, known_bytes):
    """ Return a character in bytes string form, None if it's not found. """
    # generate test plaintext of one-byte-short
    unknowns = block_size - (len(known_bytes) % block_size)
    plaintext = b'A' * (unknowns - 1)

    length = len(plaintext) + len(known_bytes) + 1  # multiple of block_size

    encrypt = lambda x: encryption(x)[:length]

    # create hash table: {ciphertext: byte_that_was_appended_to_plaintext}
    cipher = lambda x: encrypt(plaintext + known_bytes + bytes([x]))
    hash_table = {cipher(i): i for i in range(256)}

    c = encrypt(plaintext + unknown_string)
    return bytes([hash_table[c]]) if c in hash_table else None


def find_every_byte(encryption, block_size, unknown_string):
    """ Return unknown_string decrypted. """
    result = b''
    while True:
        c = find_next_byte(encryption, block_size, unknown_string, result)
        if c is None or c == b'\x04':  # '\x04' is default value for pkcs7pad
            break
        result += c
    return result


def decode_cookie(string):
    json = {}
    couples = string.split('&')
    for couple in couples:
        key, value = couple.split('=')
        clean = lambda s: s if s != '=' and s != '&' else ''
        json[key] = clean(value)
    return json

# def profile_for(json):
#     couples = ''.join( (str(k), str(v)) for k, v in json )
#     return '&'.join( '='.join( couples ) )

# def decode_cookie(cookie):
#     escape = lambda x: str(x).replace('&', '\&').replace('=', '\=')
#     # return {k: escape(v) for k, v in (rule.split('=') for rule in cookie.split('&'))}
#     return [(k, escape(v)) for k, v in (rule.split('=') for rule in cookie.split('&'))]


def encode_cookie(json):
    escape = lambda x: str(x).replace('&', '').replace('=', '')
    chunks = []
    for k, v in json.items():
        print(k, v)
        chunks.append(k + '=' + str(v).replace('&', '').replace('=', ''))
    print('&'.join(chunks))
    return '&'.join(chunks)
    # return '&'.join('='.join([k, escape(v)]) for k, v in json.items())
    # return '&'.join('='.join({k, escape(v)} for k, v in json))
    # # couples = ''.join( (str(k), str(v)) for k, v in json )
    # # return '&'.join( '='.join( couples ) )





def profile_for(usermail):
    profile = {
        'email': usermail,
        'uid': 10,
        'role': 'user'
    }
    # profile = [
    #     ('email', usermail),
    #     ('uid', 10),
    #     ('role', 'user')
    # ]
    print(profile)
    return encode_cookie(profile)
