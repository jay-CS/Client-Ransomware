import os
import base64
import constants
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding



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


def MyFileEncrypt(filepath):
    """
    Encrypts a file with a generated key.
    Creates encrypted file as 'encrypted_fileName.ext'
    INPUT:  filepath (str) path to file
    OUTPUT: c (byte str) - ciphertext
            iv - (byte str) initialization vector
            key - (byte str)
            ext - (str) file extension
    """
    key = os.urandom(constants.KEY_LEN)

    in_file = open(filepath, "rb")
    data = in_file.read()
    in_file.close()

    fileName, ext = fileInfo(filepath)

    c, iv = MyEncrypt(data, key)

    newPath = constants.FOLDER_PATH + "encrypted_" + fileName + "." + ext
    out_file = open(newPath, "wb") # writing back to file
    out_file.write(c)
    out_file.close()

    return c, iv, key, ext


def MyFileDecrypt(filepath, ext, iv, key):
    """
    Decrypts an encrypted file. 
    Creates a new file with original message as 'decrypted_fileName.ext'
    INPUT:  filepath - (str) path to encrypted file
            ext - (str) extension of file
            iv - (byte str) initialization vector
            key - (byte str) random key
    """
    in_file = open(filepath, "rb")
    data = in_file.read()
    in_file.close()

    m = MyDecrypt(data, iv, key)

    fileName = fileInfo(filepath)[0]

    newPath = constants.FOLDER_PATH + "decrypted_" + fileName + "." + ext
    out_file = open(newPath, "wb") # writing decrypted message to file
    out_file.write(m)
    out_file.close()
    
    return m


def MyEncryptMAC(message, EncKey, HMACKey):
    """
    Modified myEncrypt to include policy of Encrypt-then-MAC 
    INPUT:  message
            EncKey
            HMACKey
    OUTPUT: C (ciphertext, byte string)
            IV  (initialization vector)
            tag ()
    """
    return
    

def fileInfo(filepath):
    """
    Gets the file name and extension from a filepath
    INPUT:  filepath - (str) path to file
    OUTPUT: fileName[0] - (str) name of file
            fileName[1] - (str) extension of file
    """
    fileName = filepath.split("/")[-1]
    fileName = fileName.split(".")
    return fileName[0], fileName[1]
    

def main():
    # TESTING WITH TEXT FILE
    fileName = "test1.txt"
    c, IV, key, ext = MyFileEncrypt(constants.FOLDER_PATH + fileName)
    print(c)
    m = MyDecrypt(c, IV, key)
    print(m)


    # TESTING WITH JPEG FILE
    fileName = "face.JPG"
    c, IV, key, ext = MyFileEncrypt(constants.FOLDER_PATH + fileName)

    encryptedPath = "test-files/encrypted_" + fileName
    m = MyFileDecrypt(encryptedPath, ext, IV, key)


    # TESTING WITH PNG FILE
    fileName = "CBC.png"
    c, IV, key, ext = MyFileEncrypt(constants.FOLDER_PATH + fileName)

    encryptedPath = "test-files/encrypted_" + fileName
    m = MyFileDecrypt(encryptedPath, ext, IV, key)




main()

