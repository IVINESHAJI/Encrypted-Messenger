import os, socket, sys
from keyExchange import establishSharedKey
from chat import startChatSession

def runServer(identity, host='loclahost', port=1234) :
    
    KEY_DIR = f"client/keys/{identity}"

    if not os.path.exists(f"{KEY_DIR}/x25519PrivateKey.pem") :
        print(f"Keys not found for identity: {identity}")
        print(f"Use :- python generate_keys.py {identity} ")
        return
    
    serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serverSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        serverSocket.bind((host, port))
        serverSocket.listen(1)

        print(f"Chat server started as '{identity}'")
        print(f"Listening on {host}:{port}")
        print("Waiting for client connection...")

        clientSocket, clientAddress = serverSocket.accept()
        print(f"Connected to {clientAddress}")

        print("Performing Key Exchange.....")
        aesKey, peerIdentity = establishSharedKey(f"{KEY_DIR}/x25519PrivateKey.pem", clientSocket, isInitiator=False)

        print("Key Exchange Successful......")

        startChatSession(clientSocket, aesKey, peerIdentity, identity)
        
    except KeyboardInterrupt:
        print("\nServer interrupted........")
    except Exception as e:
        print(f"Server error: {e}")
    finally:
        serverSocket.close()
        print("Server closed.......")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python server.py <your_identity> ClientIP")
        print("Example: python server.py yourname 0.0.0.0")
        sys.exit(1)
    
    identity = sys.argv[1]
    host = sys.argv[2]
    runServer(identity, host)