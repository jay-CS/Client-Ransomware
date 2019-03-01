import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding



#How to make this more secure, remove self from being accessible 
class Encrypt():


    def __init__(self):
        #self.message =  str.encode("ascii",input("\nEnter a message: \n"))
        self.key = os.urandom(32)
    
        
    #Message is byte string varible that is encoded previosuly 
    #Data is the message with byte padding if it is not the length of 32 
    def myEncrypt(self,message):
        backend = default_backend()
        pad = padding.PKCS7(algorithms.AES.block_size).padder()
        data = pad.update(message) + pad.finalize()
        IV = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.key),modes.CBC(IV),backend = backend)
        encrypt = cipher.encryptor()
        ciphertext = encrypt.update(data) + encrypt.finalize()
        print("Ciphertext: ", ciphertext)
        return ciphertext, IV

    
    def myDecrypt(self, ciphertext, IV):
        backend = default_backend()
        cipher = Cipher(algorithms.AES(self.key),modes.CBC(IV),backend = backend)
        decrypt = cipher.decryptor()
        unpad = padding.PKCS7(algorithms.AES.block_size).unpadder()
        plain_padded = decrypt.update(ciphertext) + decrypt.finalize() 
        plaintext = unpad.update(plain_padded) + unpad.finalize()
        print("\n")
        return base64.b64decode(plaintext)
    

    def myEncryptFile(self, filename):
        with open(filename,'rb') as pic:
            text = pic.read()
            base64.b64encode(text)
        return self.myEncrypt(text)


    
    

def main():
    encrypt = Encrypt()
    #print("Decryption:",encrypt.myDecrypt(*encrypt.myEncrypt(encrypt.message)))
    #encrypt.myEncryptFile("/Users/samantharain/Desktop/378practicetext.txt")
    C,IV = encrypt.myEncryptFile("/Users/samantharain/Desktop/proxy.duckduckgo.jpg")
    pic = encrypt.myDecrypt(C,IV)
    with open("378pic.jpg","wb") as t:
        t.write(pic)
    t.close()
    
main()

