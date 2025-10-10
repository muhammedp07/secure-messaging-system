# Part A: AES Encryption
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

'''
Q2. Why is it insecure to reuse the same AES key and IV for multiple messages? (Theory)

ANS. CBC encryption is deterministic. if we encrypt the same plaintext with same AES key and IV,
we get the exact same ciphertext. Attackers can notice patterns, compare messages, and start guessing contents.
Therefore, Always use a new random IV for each message.
'''

# Part B: RSA Encryption
n = 521_895_036_569
e = 65_537
d = 140_513_163_173