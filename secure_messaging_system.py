# Part A: AES Encruption
from Crypto.Cipher import AES

# Given Parameters
AES_Key =  b"thisisasecretkey" # 16 bytes
IV = b"thisisaninitvect"        # 16 bytes
MESSAGE = b"Rendezvous at LAT 45.4215, LON -75.6972 at 22:00 local. Codeword: ORCHID."

def pkcs7_pad(data):
    pad_len = 16 - (len(data) % 16) 
    return data + bytes([pad_len]) * pad_len

def pkcs7_unpad(data):
    pad_len = data[-1]
    return data[:-pad_len]

cipher = AES.new(AES_Key, AES.MODE_CBC, IV)
ciphertext = cipher.encrypt(pkcs7_pad(MESSAGE))

decipher = AES.new(AES_Key, AES.MODE_CBC, IV)
plaintext = pkcs7_unpad(decipher.decrypt(ciphertext))