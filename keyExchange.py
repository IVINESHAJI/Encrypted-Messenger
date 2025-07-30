import os, json, struct
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization

def loadx25519PrivateKey(filename) : 
    with open(filename, "rb") as file : 
        keyBytes = file.read()
    return x25519.X25519PrivateKey.from_private_bytes(keyBytes)

def loadx25519PublicKey(filename) : 
    with open(filename, "rb") as file : 
        keyBytes = file.read()

    return x25519.X25519PublicKey.from_public_bytes(keyBytes)

def send_packet(conn, data: bytes):
    conn.sendall(struct.pack(">I", len(data)) + data)

def recv_packet(conn):
    length_data = conn.recv(4)
    if not length_data:
        raise ValueError("Connection closed before receiving packet length")
    length = struct.unpack(">I", length_data)[0]
    packet = b""
    while len(packet) < length:
        chunk = conn.recv(length - len(packet))
        if not chunk:
            raise ValueError("Connection closed during packet reception")
        packet += chunk
    return packet

def establishSharedKey(private_key_path, conn, isInitiator) :
    myPrivate = loadx25519PrivateKey(private_key_path)
    myPublic = myPrivate.public_key()

    salt = os.urandom(32)

    myPacket = json.dumps({
        "identity": os.path.basename(os.path.dirname(private_key_path)),
        "publicKey": myPublic.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        ).hex(),
        "salt": salt.hex()
    }).encode()

    if isInitiator: 
        send_packet(conn, myPacket)
        peer_packet = recv_packet(conn)

    else :
        peer_packet = recv_packet(conn)
        send_packet(conn, myPacket)

    peer_info = json.loads(peer_packet.decode())
    peer_identity = peer_info["identity"]
    peer_PubBytes = bytes.fromhex(peer_info["publicKey"])
    peer_publicBytes = x25519.X25519PublicKey.from_public_bytes(peer_PubBytes)
    peerSalt = bytes.fromhex(peer_info["salt"])

    sharedSecret = myPrivate.exchange(peer_publicBytes)

    info = b"Secured Key on the Way"

    if salt < peerSalt : 
        combinedSalt = salt + peerSalt

    else : 
        combinedSalt = peerSalt + salt

    aes_key = HKDF(
        algorithm=hashes.SHA512(),
        length=32,
        salt=combinedSalt,
        info=info
    ).derive(sharedSecret)

    return aes_key, peer_identity
