from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding 
from cryptography.hazmat.primitives import hashes, hmac
import constants
import AES_Encrypt

def GenerateRSAKeys(filepath):
    #
    #
    #
    
    exp = constants.RSA_EXPONENT
    key_len = constants.RSA_KEYSIZE
    private_key = rsa.generate_private_key(exp,key_len, backend = default_backend())
    public_key = private_key.public_key()
    WritePrivateKey(filepath,private_key)
    WritePublicKey(filepath,public_key)



def WritePrivateKey(filepath,key):
    #
    #
    #

    with open(filepath,"wb") as file:
        file.write(pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()))


def WritePublicKey(filepath, key):
    #
    #
    #

    with open(filepath,"wb") as file:
        file.write(pem = key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo))


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


def MyRSAFileEncrypt(data_file,rsa_file):
    #
    #
    #

    GenerateRSAKeys(rsa_file)
    C, IV, tag, EncKey, HMACKey, ext = AES_Encrypt.MyFileEncrypt(data_file)
    public_key = LoadRSAPublicKey(rsa_file)
    key = EncKey + HMACKey
    RSACipher = public_key.encrypt(
        key,
        padding.OAEP(
            mgf = padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return RSACipher, C, IV, tag, ext

def MyRSAFileDecrypt(RSACipher,filepath, C, IV, tag, ext, rsa_file):
    #
    #
    #

    private_key = LoadRSAPrivateKey(rsa_file)
    keys = private_key(
        RSACipher,
        padding.OAEP(
            mgf= padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    EncKey = keys[0:31]
    HMACKey = keys[32:63]
    plaintext = AES_Encrypt.MyFileDecrypt(filepath, IV, tag, EncKey, HMACKey, ext)
    return plaintext


def main():
    filepath = "happy.png"
    rsapath = ""
    RSACipher, C, IV, tag, ext = MyRSAFileEncrypt(filepath,rsapath)
    message = MyRSAFileDecrypt(RSACipher, filepath, C, IV, tag, ext, rsapath)
    print(message)

