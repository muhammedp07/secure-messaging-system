from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from datetime import datetime, timezone, timedelta

# == Part A: AES Encryption ==
# Q1.  Encrypt and decrypt the mission message using AES-CBC with the given key and IV. Show that Bob recovers the original plaintext.

# Given Parameters
AES_KEY =  b"thisisasecretkey" # 16 bytes
IV = b"thisisaninitvect"        # 16 bytes
MESSAGE = b"Rendezvous at LAT 45.4215, LON -75.6972 at 22:00 local. Codeword: ORCHID."

def pkcs7_pad(data):
    pad_len = 16 - (len(data) % 16) 
    return data + bytes([pad_len]) * pad_len

def pkcs7_unpad(data):
    pad_len = data[-1]
    return data[:-pad_len]

cipher = AES.new(AES_KEY, AES.MODE_CBC, IV)
ciphertext = cipher.encrypt(pkcs7_pad(MESSAGE))

decipher = AES.new(AES_KEY, AES.MODE_CBC, IV)
plaintext = pkcs7_unpad(decipher.decrypt(ciphertext))

'''
Q2. Why is it insecure to reuse the same AES key and IV for multiple messages? (Theory)

ANS. CBC encryption is deterministic. if we encrypt the same plaintext with same AES key and IV,
we get the exact same ciphertext. Attackers can notice patterns, compare messages, and start guessing contents.
Therefore, Always use a new random IV for each message.
'''

# == Part B: RSA Encryption ==
# Q1.  Show Python code where Alice encrypts the AES key with Bob’s RSA public key and Bob decrypts it

n = 521_895_036_569
e = 65_537
d = 140_513_163_173

# Convert AES key to integer
m = int.from_bytes(AES_KEY, "big")

# The message integer >= n, it’s too big for this small modulus.
# Split AES key into 4-byte chunks to fit safely.
def rsa_encrypt_chunk(chunk):
    m_int =int.from_bytes(chunk, "big")
    c_int = pow(m_int, e, n) # m^e mod n
    return c_int

def rsa_decrypt_chunk(c_int):
    m_int = pow(c_int, d, n)
    return m_int.to_bytes(4, "big")

# Encrypt key in chunks
chunks = [AES_KEY[i:i+4] for i in range(0, len(AES_KEY), 4)]
cipher_chunks = [rsa_encrypt_chunk(c) for c in chunks]
print("Encrypted AES key chunks: ", cipher_chunks)

# Decrypt back the key
decrypted = b''.join([rsa_decrypt_chunk(c) for c in cipher_chunks])
print("Recovered AES Key: ", decrypted)

'''
Q2. Why should RSA not be used to encrypt large files directly? (Theory)

ANS. RSA is very slow and limited to data smaller than its modulus n. It's inefficient for bulk data.
Best Practice is use RSA to encrypt a small symmetric ket, then use AES fot the file.
'''

# == Part C: Digital Signatures ==
# Q:1. Implement RSA digital signatures

def sha256_mod(msg):
    h = SHA256.new(msg).digest()
    return int.from_bytes(h, "big") % n # reduce to modulus size

def sign_message(msg):
    return pow(sha256_mod(msg), d, n)

def verify_signature(msg, sig):
    return pow(sig, e, n) == sha256_mod(msg)

sig = sign_message(MESSAGE)
print("Signature: ", sig)
print("Verification result: ", verify_signature(MESSAGE, sig))

# Q2. Modify one word in the message (e.g., change “ORCHID” to “LOTUS”). Verify with Alice’s old signature. What happens and why?

tempered = MESSAGE.replace(b"ORCHID",  b"LOTUS")
print("Tampered verification: ", verify_signature(tempered, sig)) #  Should be false 