# system imports
from base64 import b64decode
from typing import Tuple

# pycryptodome imports
from Crypto.Cipher import AES
from Crypto.Hash import MD5
from Crypto.Util.Padding import unpad

# encryption details
BLOCK_SIZE = AES.block_size
KEY_SIZE = 32
IV_SIZE = 16
SALT_SIZE = 8

# working data
PASSWORD = "TOPSY KRETT PASSWORD"
ENCRYPTED_DATA = "ENCRYPTED SSO SESSION"

def derive_key_and_iv() -> Tuple[bytes, bytes]:
    result = bytes()

    while len(result) < KEY_SIZE + IV_SIZE:
        hasher = MD5.new()
        hasher.update(result[-IV_SIZE:] + PASSWORD.encode("utf-8") + salt)
        result += hasher.digest()

    return result[:KEY_SIZE], result[KEY_SIZE : KEY_SIZE + IV_SIZE]

# get the raw encrypted data from the base64 encoded string
raw_encrypted_data = b64decode(ENCRYPTED_DATA)

# the first block is "Salted__THESALT", so we extract the salt
salt = raw_encrypted_data[SALT_SIZE:BLOCK_SIZE]

# beginning at the second block is the cipher text
cipher_text = raw_encrypted_data[BLOCK_SIZE:]

# let's do some work
key, iv = derive_key_and_iv()
cipher = AES.new(key, AES.MODE_CBC, iv)
decrypted = cipher.decrypt(cipher_text)
unpadded = unpad(decrypted, BLOCK_SIZE)

print(unpadded.decode("utf-8"))
