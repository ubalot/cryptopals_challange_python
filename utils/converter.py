import binascii
import string


def str_to_bytes(_input, encoding='utf-8'):
    _type = type(_input)
    if _type is str:
        _bytes = bytes(_input, encoding=encoding)
    elif _type is bytes:
        _bytes = _input
    return _bytes


def bytes_to_string(_input, encoding='utf-8'):
    _type = type(_input)
    if _type is str:
        _str = _input
    elif _type is bytes:
        _str = _input.decode(encoding)
    return _str


def decode_hex(_hex):
    """Decode string from hex format and return it in bytes format."""
    return binascii.a2b_hex(_hex)


def encode_hex(_bytes):
    """Encode binary string to hex string format."""
    return binascii.b2a_hex(_bytes)


def encode_base64(_bytes):
    """Encode bytes string to base64 format, return bytes data."""
    return binascii.b2a_base64(_bytes, newline=False)


def decode_base64(_base64):
    """Decode string from base64 to binary string format, then return it."""
    return binascii.a2b_base64(_base64)


def pkcs7pad(cipher_text, block_size, value=b'\x04'):
    """Return ciphertext padded with value until it reach blocksize length.
    :param cipher_text: bytes
    :param block_size: int
    :param value: bytes
    :return: bytes
    """
    length = len(cipher_text)
    pad = block_size - (length % block_size)
    return b''.join((cipher_text, value * pad))


class InvalidPkcs7PaddingException(Exception):
    pass


def is_valid_pkcs7_padding(_input):
    """
    :param _input: bytes
    :return: bool
    """
    valid_chars = string.printable + '\x04'
    for char in _input:
        if char not in valid_chars:
            raise InvalidPkcs7PaddingException
    return True