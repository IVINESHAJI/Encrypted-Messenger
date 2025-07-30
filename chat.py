import threading, time
from keyExchange import send_packet, recv_packet
from aesCrypto import encryptMessage, decryptMessage
from cryptography.exceptions import InvalidTag

class ChatSession : 

    def __init__(self, conn, aesKey, peerIdentity, myIdentity):
        self.conn = conn
        self.aesKey = aesKey
        self.peerIdentity = peerIdentity
        self.myIdentity = myIdentity
        self.running = True

    def startChat(self): 
        
        print(f"\nSecure Chat Established with {self.peerIdentity}")
        print("=" * 50)
        print("Type your messages and press Enter. Type /quit to exit.")
        print("=" * 50)

        receiverThread = threading.Thread(target=self.receiveMessages, daemon=True)
        receiverThread.start()

        self.sendMessages()

    def receiveMessages(self) :

        while self.running : 
            try : 
                encryptedMessage = recv_packet(self.conn)

                message = decryptMessage(self.aesKey, encryptedMessage)

                timeStamp = time.strftime("%H::%M::%S")
                print(f"\n[{timeStamp}]: {self.peerIdentity} : {message}")
                print(f"[{self.myIdentity}] > ", end="", flush=True)

            except ConnectionError : 
                print(f"\n Connection with {self.peerIdentity} lost")
                self.running = False

            except InvalidTag: 
                print(f"Tampered Message received from {self.peerIdentity}")

            except Exception as e :
                print(f"\n Error receiving: {e}")
                break

    def sendMessages(self) :

        while self.running: 
            try: 
                message = input(f"[{self.myIdentity}] > ")

                if message.lower() in ['/quit', '/q', '/exit'] :
                    print("Ending Session...")
                    self.running = False
                    break

                if not message.strip():
                    continue

                encryptedMessage = encryptMessage(self.aesKey, message)
                send_packet(self.conn, encryptedMessage)

            except KeyboardInterrupt: 
                print("Chat Closed By User.....")
                self.running = False
                break

            except Exception as e:
                print(f"Exception Message: {e}")
                break

        try:
            self.conn.close()
        except:
            pass

def startChatSession(conn, aesKey, peerIdentity, myIdentity): 

    chat = ChatSession(conn, aesKey, peerIdentity, myIdentity)
    chat.startChat()