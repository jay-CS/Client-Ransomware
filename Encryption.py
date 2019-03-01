import os
from cryptography.hazmat.primitives.ciphers.aead import AESCCM

def MyEncrypt():
    data = "Lagrange Interpolation Polynomial Approximation"
    aad = b"authenticated but unencrypted data"
    key = AESCCM.generate_key(bit_length=128)
    aesccm = AESCCM(key)
    nonce = os.urandom(13)
    ct = aesccm.encrypt(nonce, data, aad)
    print(ct)
    aesccm.decrypt(nonce, ct, aad)

MyEncrypt()
