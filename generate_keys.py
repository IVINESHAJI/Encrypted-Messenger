import os
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives import serialization


def saveKey(filename, key, KEY_DIR) : 
    with open(f"{KEY_DIR}/{filename}", "wb") as f:
        f.write(key)

def generateKeys(identity):

    KEY_DIR = f"client/keys/{identity}"
    os.makedirs(KEY_DIR, exist_ok=True)

    xPrivate = x25519.X25519PrivateKey.generate()
    xPublic = xPrivate.public_key()

    saveKey("x25519PrivateKey.pem", xPrivate.private_bytes(encoding=serialization.Encoding.Raw,
                                                    format=serialization.PrivateFormat.Raw,
                                                    encryption_algorithm=serialization.NoEncryption()
                                                    ), KEY_DIR)

    saveKey("x25519PublicKey.pem", xPublic.public_bytes(encoding=serialization.Encoding.Raw,
                                                    format=serialization.PublicFormat.Raw
                                                    ), KEY_DIR)

    edPrivate = ed25519.Ed25519PrivateKey.generate()
    edPublic = edPrivate.public_key()

    saveKey("ed25519PrivateKey.pem", edPrivate.private_bytes(encoding=serialization.Encoding.Raw,
                                                    format=serialization.PrivateFormat.Raw,
                                                    encryption_algorithm=serialization.NoEncryption()
                                                    ),KEY_DIR)

    saveKey("ed25519PublicKey.pem", edPublic.public_bytes(encoding=serialization.Encoding.Raw,
                                                    format=serialization.PublicFormat.Raw
                                                    ), KEY_DIR)
    
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) != 2:
        print("Usage: python generate_keys.py <identity>")
        print("Example: python generate_keys.py yourname")
    else:
        identity = sys.argv[1]
        generateKeys(identity)
        print(f"Keys generated for identity: {identity}")
        print(f"Location: client/keys/{identity}/")