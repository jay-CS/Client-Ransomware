"""
Holds constant values used for encryption and decryption
"""

IV_LEN = 16            # length of initialization vector
KEY_LEN = 32           # length of key for encryption
HMAC_KEY_LEN = 32      # length of key for HMAC tag generation key
RSA_KEYSIZE = 2048     # length of the of modulus key in bits, should be at least 2048 bits (256 bytes)
RSA_EXPONENT = 65537   # public exponent of the new key being generated
RSA_PRIVATE_KEY_PATH = "keys/private_key.pem"
RSA_PUBLIC_KEY_PATH = "keys/public_key.pem"
RSA_KEYS_FOLDER = "keys/"