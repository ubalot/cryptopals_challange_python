"""
AES is a specification for the encryption of electronic data established by
the U.S. National Institute of Standards and Technology (NIST) in 2001.
"""

from Crypto.Cipher import AES


class AES_Encryption(object):
    def __init__(self, key=None, encryption_mode='ECB'):
        self.__key = key

        if encryption_mode == 'ECB':
            self.___encryption_mode = AES.MODE_ECB
        elif encryption_mode == 'CBC':
            self.___encryption_mode = AES.MODE_CBC

        self.cipher = AES.new(key, self.___encryption_mode)

    @staticmethod
    def new(key, encryption_mode='ECB'):
        return AES_Encryption(key, encryption_mode)

    def decrypt(self, cipher_text):
        """
        :param cipher_text: bytes
        :return: bytes
        """
        return self.cipher.decrypt(cipher_text)

