import binascii


class Converter(object):
    def __init__(self, encoding='utf-8'):
        self.encoding = encoding

    def str_to_bytes(self, _input):
        _type = type(_input)
        if _type is str:
            _bytes = bytes(_input, encoding=self.encoding)
        elif _type is bytes:
            _bytes = _input
        return _bytes

    def bytes_to_string(self, _input):
        _type = type(_input)
        if _type is str:
            _str = _input
        elif _type is bytes:
            _str = _input.decode(self.encoding)
        return _str

    @staticmethod
    def decode_hex(_hex):
        """Decode string from hex format and return it in bytes format."""
        return binascii.a2b_hex(_hex)

    @staticmethod
    def encode_hex(_bytes):
        """Encode binary string to hex string format."""
        return binascii.b2a_hex(_bytes)

    @staticmethod
    def encode_base64(_bytes):
        """Encode bytes string to base64 format, return bytes data."""
        return binascii.b2a_base64(_bytes, newline=False)

    @staticmethod
    def decode_base64(_base64):
        """Decode string from base64 to binary string format, then return it."""
        return binascii.a2b_base64(_base64)
