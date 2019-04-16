import os
import base64
import constants
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import json
from cryptography.hazmat.primitives import hashes, hmac



def MyEncrypt(message, key):
    """
    Encrypts a message using AES. The message is padded if the last block length is not 32 bits.
    INPUT:  message - (byte str) message for encryptipn
            key - (byte str) random key
    OUTPUT: ciphertext (byte str) - encrypted message
            iv (initialization vector)
    """

    if len(key) < constants.KEY_LEN:
        print("ERROR: Key must be at least",constants.KEY_LEN, "bytes.")
        return

    # generating initialization vector
    iv = os.urandom(constants.IV_LEN)

    backend = default_backend()
    pad = padding.PKCS7(algorithms.AES.block_size).padder()
    data = pad.update(message) + pad.finalize()
    cipher = Cipher(algorithms.AES(key),modes.CBC(iv),backend = backend)
    encrypt = cipher.encryptor()
    ciphertext = encrypt.update(data) + encrypt.finalize()

    return ciphertext, iv


def MyDecrypt(ciphertext, iv, key):
    """
    Decryptes the cipher text to its original message
    INPUT:  ciphertext - (byte str) message to be decrypte
            iv - (initialization vector)
            key - (byte str) random key
    OUTPIT: plaintext - (byte str) decrypted message
    """
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key),modes.CBC(iv),backend = backend)
    decrypt = cipher.decryptor()
    unpad = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plain_padded = decrypt.update(ciphertext) + decrypt.finalize()
    plaintext = unpad.update(plain_padded) + unpad.finalize()

    return plaintext



def MyEncryptHMAC(message, EncKey, HMACKey):
    """
    Modified MyEncrypt to include policy of Encrypt-then-MAC
    INPUT:  message - (byte str) byte string
            EncKey - (byte str) encryption key
            HMACKey - (byte str) key for HMAC tag generation
    OUTPUT: C - (byte str) ciphertext
            IV - (byte str) initialization vector
            tag - (byte str) tag for HMAC verificatoin
    """
    C, IV = MyEncrypt(message,EncKey)
    h = hmac.HMAC(HMACKey,hashes.SHA256(),backend = default_backend())
    h.update(C)
    tag = h.finalize()
    return C, IV, tag


def MyDecryptHMAC(ciphertext, IV, tag, EncKey, HMACKey):
    """
    #C, IV, tag, EncKey, HMAC_Key
    Modified MyDecrypt to include verification of message using HMAC
    INPUT:  ciphertext - (byte str) byte string
            IV - (byte str) initialization vector
            tag - (byte str) tag bits of original message
            EncKey - (byte str) key used for encryption
            HMACKey - (btye str) key used for HMAC tag generation
    OUTPUT: plaintext - (byte str) decrypted message
    """

    h = hmac.HMAC(HMACKey, hashes.SHA256(), backend = default_backend())
    h.update(ciphertext)
    h.verify(tag)
    plaintext = MyDecrypt(ciphertext,IV, EncKey)

    return plaintext


def MyFileEncrypt(filepath):
    """
    Encrypts a file with a generated key.
    Include policy of Encrypt-then-MAC.
    Creates encrypted file as 'encrypted_fileName.ext'
    INPUT:  filepath (str) path to file
    OUTPUT: c (byte str) - ciphertext
            iv - (initialization vector)
            key - (byte str)
            fileName - (str) name of file
            ext - (str) file extension
    """
    Enckey = os.urandom(constants.KEY_LEN)
    HMAC_key = os.urandom(constants.HMAC_KEY_LEN)
    in_file = open(filepath, "rb")  # reading file as bytes
    data = in_file.read()
    in_file.close()

    fileName, ext = fileInfo(filepath)

    c, iv, tag = MyEncryptHMAC(data, Enckey, HMAC_key)

    return c, iv, tag, Enckey, HMAC_key, fileName, ext


def MyFileDecrypt(filepath, C, IV, tag, EncKey, HMAC_Key, ext):
    """
    #filepath, C, IV, tag, EncKey, HMACKey, ext
    Decrypts an encrypted file. Include policy of Encrypt-then-MAC.
    Creates a new file with original message as 'decrypted_fileName.ext'
    INPUT:  filepath - (str) path to encrypt8 v b bed file
            ext - (str) extension of file
            iv - (byte str) initialization vector
            key - (byte str) random key
    OUTPUT: m - (byte str) original message
    """

    plaintext = MyDecryptHMAC(C, IV, tag, EncKey, HMAC_Key)

    return filepath, plaintext




def fileInfo(filepath):
    """
    Gets the file name and extension from a filepath
    INPUT:  filepath - (str) path to file
    OUTPUT: fileName[0] - (str) name of file
            fileName[1] - (str) extension of file
    """
    fileName = filepath.split("/")[-1]
    fileName = fileName.split(".")
    ext = fileName.pop()
    return '.'.join(fileName), ext



def main():

    filepath = "test-files/378practice.txt"
    print(fileInfo(filepath))

# main()