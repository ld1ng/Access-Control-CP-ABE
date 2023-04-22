from Crypto import Random
from Crypto.Cipher import AES
import base64
from hashlib import md5
 
def pad(data):
    length = 16 - (len(data) % 16)
    return data + chr(length).encode()*length
 
def unpad(data):
    return data[:-(data[-1] if type(data[-1]) == int else ord(data[-1]))]
 
def bytes_to_key(data, salt, output=48):
    assert len(salt) == 8, len(salt)
    data += salt
    key = md5(data).digest()
    final_key = key
    while len(final_key) < output:
        key = md5(key + data).digest()
        final_key += key
    return final_key[:output]
 
def encrypt(message, passphrase):
    salt = Random.new().read(8)
    key_iv = bytes_to_key(passphrase, salt, 32+16)
    key = key_iv[:32]
    iv = key_iv[32:]
    aes = AES.new(key, AES.MODE_CBC, iv)
    return base64.b64encode(b"Salted__" + salt + aes.encrypt(pad(message)))
 
def decrypt(encrypted, passphrase):
    encrypted = base64.b64decode(encrypted)
    assert encrypted[0:8] == b"Salted__"
    salt = encrypted[8:16]
    key_iv = bytes_to_key(passphrase, salt, 32+16)
    key = key_iv[:32]
    iv = key_iv[32:]
    aes = AES.new(key, AES.MODE_CBC, iv)
    return unpad(aes.decrypt(encrypted[16:]))
 
if __name__ == '__main__':
 
    key = b'692142b69d5814787dc80d993ca277d64a35d5727161690ef72e1aeb916d2382'
    data = b'If the day is done, if birds sing no more, if the wind has flagged tired, then draw the veil of darkness thick upon me, even as thou hast wrapt the earth with the coverlet of sleep and tenderly closed the petals of the drooping lotus at dusk.From the traveller, whose sack of provisions is empty before the voyage is ended, whose garment is torn and dustladen, whose strength is exhausted, remove shame and poverty, and renew his life like a flower under the cover of thy kindly night.'
    encrypt_data = encrypt(data, key)
    print(encrypt_data)
 
    decrypt_data = decrypt(encrypt_data, key)
    print(decrypt_data)