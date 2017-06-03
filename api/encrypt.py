from hashlib import md5
from Crypto.Cipher import AES
from Padding import appendPadding

from logging import getLogger
log = getLogger(__name__)

class MT5AES(object):

    def __init__(self, password, crypt_rand):
        self.password = password
        if isinstance(crypt_rand, str):
            # Split to 16-byte pieces
            self.crypt_rand = [crypt_rand[2*16*i:2*16*(i+1)] for i in range(16)]
        else:
            self.crypt_rand = crypt_rand

        log.debug("CRYPT_RAND={}".format(self.crypt_rand))
        self.crypt_iv = self._get_crypt_iv()
        self.aes_key = self.crypt_iv[0] + self.crypt_iv[1]
        self.encrypt_iv = self.crypt_iv[2]
        self.decrypt_iv = self.crypt_iv[3]

        self.crypter = AES.new(self.aes_key, AES.MODE_OFB, self.encrypt_iv)
        self.decrypter = AES.new(self.aes_key, AES.MODE_OFB, self.decrypt_iv)
        # super(MT5AES, self).__init__()

    def _get_crypt_iv(self):
        t1 = md5(self.password.encode('utf-16le')).digest()
        # important - no utf16 between hashes!
        t2 = 'WebAPI'
        pwd_hash = md5(t1 + t2).digest()
        crypt_iv = []
        out = pwd_hash
        for i in range(16):
            out = md5(bytearray(self.crypt_rand[i].decode('hex') + out)).digest()
            crypt_iv.append(out)
        return crypt_iv

    def encrypt(self, data):
        initial_len = len(data)
        padded = appendPadding(data)
        return self.crypter.encrypt(padded)[:initial_len]

    def decrypt(self, data):
        initial_len = len(data)
        padded = appendPadding(data)
        return self.decrypter.encrypt(padded)[:initial_len]
