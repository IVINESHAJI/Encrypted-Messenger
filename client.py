#!/usr/bin/env python3
import socket
import sys
import os
from keyExchange import establishSharedKey
from chat import startChatSession

def run_client(identity, server_host='localhost', server_port=8888):
    """Run the chat client"""
    key_dir = f"client/keys/{identity}"
    private_key_path = f"{key_dir}/x25519PrivateKey.pem"
    
    if not os.path.exists(private_key_path):
        print(f"Keys not found for identity '{identity}'")
        print(f"Please run: python generate_keys.py {identity}")
        return
    
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    try:
        print(f"Starting chat client as '{identity}'")
        print(f"Connecting to {server_host}:{server_port}...")
        
        client_socket.connect((server_host, server_port))
        print("Connected to server......")
        print("Performing key exchange...")
        aes_key, peer_identity = establishSharedKey(private_key_path, client_socket, isInitiator=True)
        
        print(f"Key exchange successful with '{peer_identity}'")
        
        startChatSession(client_socket, aes_key, peer_identity, identity)
        
    except ConnectionRefusedError:
        print(f"[-]Could not connect to {server_host}:{server_port}")
        print("Make sure the server is running!")
    except KeyboardInterrupt:
        print("\nClient interrupted............")
    except Exception as e:
        print(f"Client error: {e}")
    finally:
        client_socket.close()
        print("Client socket closed..........")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python client.py <your_identity> [server_host] [server_port]")
        print("Example: python client.py yourname")
        print("Example: python client.py yourname 192.168.1.100 8888")
        sys.exit(1)
    
    identity = sys.argv[1]
    server_host = sys.argv[2] if len(sys.argv) > 2 else 'localhost'
    server_port = int(sys.argv[3]) if len(sys.argv) > 3 else 8888
    
    run_client(identity, server_host, server_port)