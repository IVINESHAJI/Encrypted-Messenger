import os 
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

def encryptMessage(aesKey: bytes, plaintext: str) -> bytes :
    
    aesgcm = AESGCM(aesKey)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)
    
    return nonce + ciphertext

def decryptMessage(aesKey: bytes, encryptedData: bytes) -> str:

    if len(encryptedData) < 12 : 
        raise ValueError("Encrypted Data too Short")
    
    nonce = encryptedData[:12]
    ciphertext = encryptedData[12:]

    aesgcm = AESGCM(aesKey)

    try: 
        plaintextBytes = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintextBytes
    
    except InvalidTag: 
        raise InvalidTag("Message authentication failed")
    
    except UnicodeDecodeError: 
        raise UnicodeDecodeError("Decrypted data is not valid UTF-8")