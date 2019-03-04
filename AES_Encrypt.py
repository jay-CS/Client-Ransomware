import os
import base64
import constants
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding



def myEncrypt(message, key):
    """
    Encrypts a message using AES. The message is padded if the last block length is not 32 bits.
    INPUT:  message (message for encryption, byte string)
    OUTPUT: ciphertext (encrypted message, byte string)
            IV (initialization vector)
    """

    if len(key) < constants.KEY_LEN:
        print("ERROR: Key must be at least",constants.KEY_LEN, "bytes.")
        return 

    # generating initialization vector
    IV = os.urandom(constants.IV_LEN)   

    backend = default_backend()
    pad = padding.PKCS7(algorithms.AES.block_size).padder()
    data = pad.update(message) + pad.finalize()
    cipher = Cipher(algorithms.AES(key),modes.CBC(IV),backend = backend)
    encrypt = cipher.encryptor()
    ciphertext = encrypt.update(data) + encrypt.finalize()

    return ciphertext, IV


def myDecrypt(ciphertext, IV, key):
    """
    Decryptes the cipher text to its original message
    INPUT:  ciphertext - (byte str) message to be decrypted, byte string
            IV - (byte str) initialization vector
            key - (byte str)
    OUTPIT: plaintext - (byte str) decrypted message
    """
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key),modes.CBC(IV),backend = backend)
    decrypt = cipher.decryptor()
    unpad = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plain_padded = decrypt.update(ciphertext) + decrypt.finalize() 
    plaintext = unpad.update(plain_padded) + unpad.finalize()

    return plaintext


def myFileEncrypt(filepath):
    """
    Encrypts a file with a generated key.
    Creates encrypted file as 'encryptedFile.ext'
    INPUT:  filepath (path to file, string)
    OUTPUT: c (byte str) - ciphertext
            IV - (byte str) initialization vector
            key - (byte str)
            ext - (str) file extension
    """
    key = os.urandom(constants.KEY_LEN)

    in_file = open(filepath, "rb")
    data = in_file.read()
    in_file.close()
    path = filepath.split(".")
    ext = "." + path[-1]

    c, IV = myEncrypt(data, key)

    newPath = "test-files/encryptedFile" + ext
    out_file = open(newPath, "wb") # writing back to file
    out_file.write(c)
    out_file.close()

    return c, IV, key, ext


def myFileDecrypt(filepath, ext, IV, key):
    """
    Decrypts an encrypted file. 
    Creates a new file with original message as 'decryptedFile.ext'
    INPUT:  filepath - (str) path to encrypted file
            ext - (str) extension of file
            IV - (byte str) initialization vector
            key - (byte str)
    """
    in_file = open(filepath, "rb")
    data = in_file.read()
    in_file.close()

    m = myDecrypt(data, IV, key)

    newPath = "test-files/decryptedFile" + ext
    out_file = open(newPath, "wb") # writing decrypted message to file
    out_file.write(m)
    out_file.close()
    return m


def myEncryptMAC(message, EncKey, HMACKey):
    """
    Modified myEncrypt to include policy of Encrypt-then-MAC 
    INPUT:  message
            EncKey
            HMACKey
    OUTPUT: C (ciphertext, byte string)
            IV  (initialization vector)
            tag ()
    """
    if len(EncKey) < constants.KEY_LEN:
        print("ERROR: Key must be at least",constants.KEY_LEN, "bytes.")
        return 

    IV = os.urandom(constants.IV_LEN)   # GENERATING IV

    return
    
    

def main():
    # TESTING WITH TEXT FILE
    c, IV, key, ext = myFileEncrypt("test-files/test1.txt")
    print(c)
    m = myDecrypt(c, IV, key)
    print(m)


    # TESTING WITH JPEG FILE
    c, IV, key, ext = myFileEncrypt("test-files/face.JPG")

    encryptedPath = "test-files/encryptedFile" + ext
    m = myFileDecrypt(encryptedPath, ext, IV, key)


    # TESTING WITH PNG FILE
    c, IV, key, ext = myFileEncrypt("test-files/CBC.png")

    encryptedPath = "test-files/encryptedFile" + ext
    m = myFileDecrypt(encryptedPath, ext, IV, key)




main()

