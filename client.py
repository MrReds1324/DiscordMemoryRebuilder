import socket
import struct
import threading
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from utils import Connection, Signal

client_8_bytes = get_random_bytes(8)


def connect_to_server(connection: Connection) -> bool:
    attempts = 0
    while attempts < 5:
        try:
            attempts += 1
            connection.socket.connect((connection.address, connection.port))
            print("[!] Connection Successful")
            return True
        except:
            print(f"[!] Attempts remaining: {5 - attempts}")

    return False


def initiate_handshake(connection: Connection) -> bool:
    pass


def receive_data_frames() -> bytes:
    pass


if __name__ == "__main__":
    # Read in stored RSA keys here
    # with open('client_private.pem', 'rb'):
    #     pass
    # with open('client_public.pem', 'rb'):
    #     pass
    # Otherwise generate new RSA keys here

    server = Connection('server')
    server.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.address = "127.0.0.1"
    server.port = 8080

    # When we have connected to the server, send the uid and initiate the handshake
    if connect_to_server(server):
        server.send(struct.pack('>Q', len(b'test')))
        server.send(b'test')
        initiate_handshake(server)
        server.send(Signal.READY)

        server.receive(1024)
